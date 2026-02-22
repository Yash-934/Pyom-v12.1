package com.pyom

import android.content.ContentValues
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import okhttp3.OkHttpClient
import okhttp3.Request
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.ZipFile

class MainActivity : FlutterActivity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var currentProcess: Process? = null
    private val isSetupCancelled = AtomicBoolean(false)

    private val okHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .followRedirects(true).followSslRedirects(true)
            .retryOnConnectionFailure(true).build()
    }
    private val executor = Executors.newCachedThreadPool()

    private val extDir get() = getExternalFilesDir(null) ?: filesDir
    private val envRoot get() = File(extDir, "linux_env")
    private val binDir get() = File(codeCacheDir, "bin")
    private val prootVersionFile get() = File(binDir, "proot.version")
    private val envConfigFile get() = File(filesDir, "env_config.json")
    private val prootBundledBin get() = File(applicationInfo.nativeLibraryDir, "libproot.so")
    private val prootExtractedBin get() = File(binDir, "proot")

    private val prootBin: File
        get() {
            val v = prootVersionFile.takeIf { it.exists() }?.readText()?.trim() ?: ""
            if (v.startsWith("alt-path:")) {
                val f = File(v.removePrefix("alt-path:")); if (f.exists()) return f
            }
            if (prootBundledBin.exists()) return prootBundledBin
            return prootExtractedBin
        }

    private val rootfsSources = mapOf(
        "alpine" to listOf(
            "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.1-aarch64.tar.gz",
            "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.1-aarch64.tar.gz",
            "https://mirrors.ustc.edu.cn/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.1-aarch64.tar.gz",
            "https://mirror.nju.edu.cn/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.1-aarch64.tar.gz",
        ),
        "ubuntu" to listOf(
            "https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.3-base-arm64.tar.gz",
            "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-cdimage/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.3-base-arm64.tar.gz",
            "https://mirrors.ustc.edu.cn/ubuntu-cdimage/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.3-base-arm64.tar.gz",
            "https://mirrors.aliyun.com/ubuntu-cdimage/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.3-base-arm64.tar.gz",
        ),
    )

    private var eventSink: EventChannel.EventSink? = null
    private val CHANNEL = "com.pyom/linux_environment"
    private val OUTPUT_CHANNEL = "com.pyom/process_output"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // ── Register Termux native terminal PlatformView ──────────────────────
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "com.pyom/termux_terminal_view",
            TermuxViewFactory(flutterEngine.dartExecutor.binaryMessenger)
        )

        // ── Termux session args channel ───────────────────────────────────────
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "com.pyom/termux_session")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getProotSessionArgs" -> {
                        val envId = call.argument<String>("envId")
                            ?: getInstalledEnvironment()?.get("id") as String?
                            ?: run { result.error("NO_ENV", "No environment installed", null); return@setMethodCallHandler }
                        val envDir = File(envRoot, envId)
                        val pErr = ensureProotBinary()
                        if (pErr != null) { result.error("NO_PROOT", pErr, null); return@setMethodCallHandler }
                        val shell = findShellInEnv(envDir)
                        if (shell == null) { result.error("NO_SHELL", "No shell found in rootfs", null); return@setMethodCallHandler }
                        val tmpDir = File(envDir, "tmp").apply { mkdirs(); setWritable(true, false) }
                        val wrapperScript = File(extDir, "bin/proot_shell.sh")
                        wrapperScript.parentFile?.mkdirs()
                        wrapperScript.writeText("""
                            #!/system/bin/sh
                            export PROOT_NO_SECCOMP=1
                            export PROOT_TMP_DIR="${tmpDir.absolutePath}"
                            export HOME=/root
                            export USER=root
                            export TERM=xterm-256color
                            export LANG=C.UTF-8
                            export LC_ALL=C.UTF-8
                            export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
                            export LD_PRELOAD=
                            exec "${prootBin.absolutePath}" \
                                --link2symlink -k 5.4.0 \
                                -r "${envDir.absolutePath}" \
                                -w /root \
                                -b /dev -b /proc -b /sys \
                                -b "${extDir.absolutePath}:/data_internal" \
                                -0 $shell -l
                        """.trimIndent())
                        wrapperScript.setExecutable(true, false)
                        result.success(mapOf(
                            "shellPath" to "/system/bin/sh",
                            "cwd" to extDir.absolutePath,
                            "env" to listOf(
                                "PROOT_NO_SECCOMP=1",
                                "PROOT_TMP_DIR=${tmpDir.absolutePath}",
                                "HOME=/root", "TERM=xterm-256color",
                                "LANG=C.UTF-8",
                                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                "WRAPPER=${wrapperScript.absolutePath}"
                            )
                        ))
                    }
                    else -> result.notImplemented()
                }
            }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, OUTPUT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(a: Any?, sink: EventChannel.EventSink?) { eventSink = sink }
                override fun onCancel(a: Any?) { eventSink = null }
            })

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setupEnvironment" -> {
                        isSetupCancelled.set(false)
                        val distro = call.argument<String>("distro") ?: "alpine"
                        val envId  = call.argument<String>("envId")  ?: "alpine"
                        executor.execute { setupEnvironment(distro, envId, result) }
                    }
                    "cancelSetup" -> { isSetupCancelled.set(true); result.success(null) }
                    "executeCommand" -> executeCommand(call, result)
                    "isEnvironmentInstalled" -> {
                        val envId = call.argument<String>("envId") ?: ""
                        result.success(isEnvironmentInstalled(envId))
                    }
                    "getInstalledEnvironment" -> result.success(getInstalledEnvironment())
                    "listEnvironments" -> result.success(listEnvironments())
                    "deleteEnvironment" -> {
                        val envId = call.argument<String>("envId") ?: ""
                        result.success(deleteEnvironment(envId))
                    }
                    "getStorageInfo" -> {
                        val prootCheckError = ensureProotBinary()
                        result.success(mapOf(
                            "filesDir"     to filesDir.absolutePath,
                            "envRoot"      to envRoot.absolutePath,
                            "freeSpaceMB"  to (extDir.freeSpace / 1048576L),
                            "totalSpaceMB" to (extDir.totalSpace / 1048576L),
                            "prootVersion" to (prootVersionFile.takeIf { it.exists() }?.readText()?.trim() ?: "bundled"),
                            "prootPath"    to prootBin.absolutePath,
                            "prootExists"  to (prootCheckError == null),
                            "prootError"   to prootCheckError
                        ))
                    }
                    else -> result.notImplemented()
                }
            }
    }

    // ─── PROOT BINARY ─────────────────────────────────────────────────────────
    private fun isActuallyExecutable(file: File): Boolean {
        if (!file.exists()) return false
        return try {
            val proc = ProcessBuilder(file.absolutePath, "--version").redirectErrorStream(true).start()
            val exited = proc.waitFor(3, TimeUnit.SECONDS)
            if (!exited) { proc.destroyForcibly(); return true }
            val code = proc.exitValue()
            code != 126 && code != 127
        } catch (e: Exception) {
            val msg = e.message ?: ""
            !msg.contains("error=13") && !msg.contains("error=8") &&
            !msg.contains("Permission denied") && !msg.contains("ENOEXEC")
        }
    }

    private fun ensureProotBinary(): String? {
        if (prootBundledBin.exists() && isActuallyExecutable(prootBundledBin)) return null
        if (prootExtractedBin.exists() && isActuallyExecutable(prootExtractedBin)) return null

        val extractError = tryExtractProot(prootExtractedBin)
        if (extractError == null && isActuallyExecutable(prootExtractedBin)) {
            prootVersionFile.writeText("extracted-from-assets"); return null
        }

        val candidates = listOf(
            File(filesDir.parent ?: filesDir.absolutePath, "code_cache/bin/proot"),
            File(applicationInfo.dataDir, "code_cache/bin/proot"),
        )
        for (candidate in candidates) {
            if (tryExtractProot(candidate) == null && isActuallyExecutable(candidate)) {
                prootVersionFile.writeText("alt-path:${candidate.absolutePath}"); return null
            }
        }

        val nativeFiles = File(applicationInfo.nativeLibraryDir).listFiles()
            ?.take(8)?.joinToString(", ") { it.name } ?: "none"
        return "FATAL: Cannot execute proot binary.\n" +
               "nativeLibDir: [$nativeFiles]\n" +
               "codeCacheDir: ${prootExtractedBin.absolutePath} (exists=${prootExtractedBin.exists()})\n" +
               "extractError: ${extractError ?: "exec test failed"}"
    }

    private fun tryExtractProot(dest: File): String? {
        return try {
            dest.parentFile?.mkdirs()
            // PRIMARY: assets/proot-arm64 (ELF executable must be in assets, not jniLibs)
            try {
                assets.open("proot-arm64").use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                }
                dest.setExecutable(true, false)
                Runtime.getRuntime().exec(arrayOf("chmod", "755", dest.absolutePath))
                    .waitFor(2, TimeUnit.SECONDS)
                return null
            } catch (_: Exception) {}

            // FALLBACK: scan APK lib/ entries
            val abiCandidates = listOf("lib/arm64-v8a/libproot.so", "lib/aarch64/libproot.so")
            ZipFile(applicationInfo.sourceDir).use { zip ->
                val entry = abiCandidates.mapNotNull { zip.getEntry(it) }.firstOrNull()
                    ?: return "proot not found in assets or APK"
                zip.getInputStream(entry).use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
                dest.setExecutable(true, false)
                Runtime.getRuntime().exec(arrayOf("chmod", "755", dest.absolutePath))
                    .waitFor(2, TimeUnit.SECONDS)
            }
            null
        } catch (e: Exception) { e.message }
    }

    // ─── ENVIRONMENT MANAGEMENT ───────────────────────────────────────────────
    private fun isEnvironmentInstalled(envId: String): Boolean {
        val envDir = File(envRoot, envId)
        if (!envDir.exists()) return false
        if (File(envDir, "etc/os-release").exists()) return true
        return findShellInEnv(envDir) != null
    }

    private fun getInstalledEnvironment(): Map<String, Any>? =
        listEnvironments().firstOrNull { it["exists"] as Boolean }

    private fun deleteEnvironment(envId: String): Boolean = try {
        File(envRoot, envId).takeIf { it.exists() }?.deleteRecursively()
        envConfigFile.takeIf { it.exists() }?.delete(); true
    } catch (_: Exception) { false }

    private fun listEnvironments(): List<Map<String, Any>> {
        if (!envRoot.exists()) return emptyList()
        return envRoot.listFiles()?.filter { it.isDirectory }?.map { dir ->
            mapOf("id" to dir.name, "path" to dir.absolutePath, "exists" to isEnvironmentInstalled(dir.name))
        } ?: emptyList()
    }

    private fun sendProgress(msg: String, progress: Double) {
        mainHandler.post {
            flutterEngine?.dartExecutor?.binaryMessenger?.let { messenger ->
                MethodChannel(messenger, CHANNEL).invokeMethod("onSetupProgress",
                    mapOf("message" to msg, "progress" to progress))
            }
        }
    }

    // ─── SETUP ────────────────────────────────────────────────────────────────
    private fun setupEnvironment(distro: String, envId: String, result: MethodChannel.Result) {
        try {
            val envDir = File(envRoot, envId)
            if (isEnvironmentInstalled(envId)) {
                sendProgress("✅ Environment already installed!", 1.0)
                mainHandler.post { result.success(mapOf("success" to true, "alreadyInstalled" to true)) }
                return
            }
            envDir.mkdirs()

            val prootError = ensureProotBinary()
            if (prootError != null) { mainHandler.post { result.error("SETUP_ERROR", prootError, null) }; return }
            sendProgress("✅ proot ready", 0.05)
            if (isSetupCancelled.get()) { mainHandler.post { result.error("CANCELLED", "Cancelled", null) }; return }

            sendProgress("🌐 Checking network…", 0.08)
            checkNetworkOrThrow()

            sendProgress("Downloading $distro rootfs…", 0.10)
            val tarFile = File(extDir, "rootfs_${envId}.tar.gz")
            downloadWithFallback(rootfsSources[distro] ?: rootfsSources["alpine"]!!, tarFile, 0.10, 0.60)
            if (isSetupCancelled.get()) { tarFile.delete(); mainHandler.post { result.error("CANCELLED", "Cancelled", null) }; return }

            sendProgress("Extracting rootfs…", 0.62)
            extractTarGz(tarFile, envDir); tarFile.delete()
            if (isSetupCancelled.get()) { mainHandler.post { result.error("CANCELLED", "Cancelled", null) }; return }

            sendProgress("🔧 Repairing rootfs symlinks…", 0.73)
            repairRootfsShell(envDir)

            sendProgress("Configuring environment…", 0.75)
            File(envDir, "etc/resolv.conf").writeText("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
            listOf("tmp", "root", "proc", "sys", "dev").forEach { File(envDir, it).mkdirs() }

            sendProgress("Installing Python & build tools…", 0.78)
            val installCmd = if (distro == "ubuntu")
                "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-dev gcc g++ make curl wget && pip3 install --upgrade pip setuptools wheel"
            else
                "apk add --no-cache python3 py3-pip python3-dev gcc musl-dev make curl wget"
            runCommandInProot(envId, installCmd, "/", 600_000)

            saveEnvConfig(envId, distro)
            sendProgress("✅ Environment ready!", 1.0)
            mainHandler.post { result.success(mapOf("success" to true)) }
        } catch (e: Exception) {
            mainHandler.post { result.error("SETUP_ERROR", e.message ?: "Unknown error", null) }
        }
    }

    private fun saveEnvConfig(envId: String, distro: String) {
        try {
            envConfigFile.writeText("""{"envId": "$envId", "distro": "$distro", "installedAt": ${System.currentTimeMillis()}}""")
        } catch (_: Exception) {}
    }

    private fun executeCommand(call: MethodCall, result: MethodChannel.Result) {
        executor.execute {
            try {
                val envId = call.argument<String>("environmentId") ?: getInstalledEnvironment()?.get("id") as String? ?: ""
                val command = call.argument<String>("command") ?: ""
                val workingDir = call.argument<String>("workingDir") ?: "/"
                val timeoutMs = call.argument<Int>("timeoutMs") ?: 300000
                if (envId.isEmpty()) { mainHandler.post { result.error("EXEC_ERROR", "No Linux environment found.", null) }; return@execute }
                mainHandler.post { result.success(runCommandInProot(envId, command, workingDir, timeoutMs)) }
            } catch (e: Exception) {
                mainHandler.post { result.error("EXEC_ERROR", e.message, null) }
            }
        }
    }

    // ─── ROOTFS REPAIR ────────────────────────────────────────────────────────
    private fun repairRootfsShell(envDir: File) {
        val binDir = File(envDir, "bin")
        val usrBinDir = File(envDir, "usr/bin")
        if (!binDir.exists() && !java.nio.file.Files.isSymbolicLink(binDir.toPath())) {
            if (usrBinDir.exists()) binDir.mkdirs()
        }
        val busybox = listOf("bin/busybox","usr/bin/busybox","sbin/busybox","usr/sbin/busybox")
            .map { File(envDir, it) }.firstOrNull { it.exists() || java.nio.file.Files.isSymbolicLink(it.toPath()) }
        val shellInUsrBin = listOf("usr/bin/sh","usr/bin/bash","usr/local/bin/sh")
            .map { File(envDir, it) }.firstOrNull { it.exists() }
        val binSh = File(envDir, "bin/sh")
        if (!binSh.exists()) {
            when {
                shellInUsrBin != null -> { binDir.mkdirs(); try { shellInUsrBin.copyTo(binSh, true); binSh.setExecutable(true, false) } catch (_: Exception) {} }
                busybox != null -> { binDir.mkdirs(); try { val bb = File(envDir, "bin/busybox"); if (!bb.exists()) { busybox.copyTo(bb, true); bb.setExecutable(true, false) }; bb.copyTo(binSh, true); binSh.setExecutable(true, false) } catch (_: Exception) {} }
                else -> { binDir.mkdirs(); envDir.walk().filter { it.isFile && (it.name == "sh" || it.name == "bash" || it.name == "busybox") }.firstOrNull()?.let { try { it.copyTo(binSh, true); binSh.setExecutable(true, false) } catch (_: Exception) {} } }
            }
        }
        if (binSh.exists()) binSh.setExecutable(true, false)
        val usrBinEnv = File(envDir, "usr/bin/env")
        if (!usrBinEnv.exists() && binSh.exists()) { usrBinDir.mkdirs(); try { usrBinEnv.writeText("#!/bin/sh\nexec \"\$@\"\n"); usrBinEnv.setExecutable(true, false) } catch (_: Exception) {} }
        File(envDir, "tmp").apply { mkdirs(); setWritable(true, false) }
    }

    private fun findShellInEnv(envDir: File): String? {
        for (p in listOf("/bin/bash","/bin/sh","/usr/bin/bash","/usr/bin/sh","/usr/local/bin/bash","/usr/local/bin/sh","/bin/busybox","/usr/bin/busybox")) {
            val f = File(envDir, p.drop(1))
            if (f.exists() || java.nio.file.Files.isSymbolicLink(f.toPath())) return p
        }
        return try { envDir.walk().filter { it.isFile && (it.name == "sh" || it.name == "bash") }.firstOrNull()?.absolutePath?.removePrefix(envDir.absolutePath) } catch (_: Exception) { null }
    }

    // ─── RUN IN PROOT (via wrapper script — guarantees PROOT_NO_SECCOMP) ─────
    private fun runCommandInProot(envId: String, command: String, workingDir: String, timeoutMs: Int): Map<String, Any> {
        val pErr = ensureProotBinary()
        if (pErr != null) return mapOf("stdout" to "", "exitCode" to -1, "stderr" to pErr)
        val envDir = File(envRoot, envId)
        if (!envDir.exists()) return mapOf("stdout" to "", "exitCode" to -1, "stderr" to "Env not found: ${envDir.absolutePath}")
        val shell = findShellInEnv(envDir)
            ?: return mapOf("stdout" to "", "exitCode" to -1, "stderr" to "No shell in rootfs. Delete env and reinstall.")
        val tmpDir = File(envDir, "tmp").apply { mkdirs(); setWritable(true, false) }

        // Wrapper script guarantees PROOT_NO_SECCOMP=1 reaches proot at init time
        val wrapper = File(extDir, "bin/proot_cmd.sh")
        wrapper.parentFile?.mkdirs()
        val escapedCmd = command.replace("\"", "\\\"")
        wrapper.writeText("""
            #!/system/bin/sh
            export PROOT_NO_SECCOMP=1
            export PROOT_TMP_DIR="${tmpDir.absolutePath}"
            export HOME=/root
            export TERM=xterm-256color
            export LANG=C.UTF-8
            export LC_ALL=C.UTF-8
            export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            export TMPDIR="${tmpDir.absolutePath}"
            export LD_PRELOAD=
            exec "${prootBin.absolutePath}" \
                --link2symlink -k 5.4.0 \
                -r "${envDir.absolutePath}" \
                -w "$workingDir" \
                -b /dev -b /proc -b /sys \
                -b "${extDir.absolutePath}:/data_internal" \
                -0 $shell -c "$escapedCmd"
        """.trimIndent())
        wrapper.setExecutable(true, false)

        val pb = ProcessBuilder(listOf("/system/bin/sh", wrapper.absolutePath)).apply {
            directory(extDir)
            redirectErrorStream(false)
            environment().apply {
                put("PROOT_NO_SECCOMP", "1")
                put("PROOT_TMP_DIR", tmpDir.absolutePath)
                put("HOME", "/root"); put("TERM", "xterm-256color")
                put("LANG", "C.UTF-8"); put("LD_PRELOAD", "")
            }
        }
        return try {
            val process = pb.start(); currentProcess = process
            val stdout = StringBuilder(); val stderr = StringBuilder()
            val t1 = Thread { process.inputStream.bufferedReader().lines().forEach { stdout.append(it).append("\n"); mainHandler.post { eventSink?.success(it) } } }
            val t2 = Thread { process.errorStream.bufferedReader().lines().forEach { stderr.append(it).append("\n"); mainHandler.post { eventSink?.success("[err] $it") } } }
            t1.start(); t2.start()
            val done = process.waitFor(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            t1.join(1000); t2.join(1000)
            if (done) mapOf("stdout" to stdout.toString(), "stderr" to stderr.toString(), "exitCode" to process.exitValue())
            else { process.destroyForcibly(); mapOf("stdout" to stdout.toString(), "stderr" to "Timed out after ${timeoutMs}ms", "exitCode" to -1) }
        } catch (e: Exception) {
            mapOf("stdout" to "", "stderr" to "Process error: ${e.message}", "exitCode" to -1)
        }
    }

    // ─── NETWORK ──────────────────────────────────────────────────────────────
    private fun bindToActiveNetwork() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.activeNetwork?.let { cm.bindProcessToNetwork(it) }
        } catch (_: Exception) {}
    }

    private fun checkNetworkOrThrow() {
        bindToActiveNetwork()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val ok = caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        if (!ok) throw Exception("❌ No internet connection. Check WiFi/mobile data.")
    }

    private fun downloadWithFallback(mirrors: List<String>, dest: File, ps: Double, pe: Double) {
        bindToActiveNetwork(); var lastEx: Exception? = null
        mirrors.forEachIndexed { i, url ->
            if (isSetupCancelled.get()) throw Exception("Cancelled")
            try { sendProgress("📥 Mirror ${i+1}/${mirrors.size}…", ps + 0.01); downloadWithProgress(url, dest, ps, pe); return }
            catch (e: Exception) {
                lastEx = e; if (e.message?.contains("cancelled") == true) throw e
                sendProgress("⚠️ Mirror ${i+1} failed…", ps + 0.02); dest.takeIf { it.exists() }?.delete(); bindToActiveNetwork()
            }
        }
        throw Exception("❌ All mirrors failed. ${lastEx?.message}")
    }

    private fun downloadWithProgress(urlStr: String, dest: File, ps: Double, pe: Double) {
        bindToActiveNetwork()
        okHttpClient.newCall(Request.Builder().url(urlStr).header("User-Agent","Pyom-IDE/1.0 Android").build()).execute().use { resp ->
            if (!resp.isSuccessful) throw Exception("HTTP ${resp.code}")
            val body = resp.body ?: throw Exception("Empty body")
            val total = body.contentLength(); var downloaded = 0L; var lastMs = System.currentTimeMillis()
            body.byteStream().use { input -> FileOutputStream(dest).use { out ->
                val buf = ByteArray(65536); var n: Int
                while (input.read(buf).also { n = it } != -1) {
                    if (isSetupCancelled.get()) throw Exception("Cancelled")
                    out.write(buf, 0, n); downloaded += n
                    val now = System.currentTimeMillis()
                    if (now - lastMs > 900) { lastMs = now
                        val ratio = if (total > 0) downloaded.toDouble() / total else 0.4
                        val p = (ps + ratio * (pe - ps)).coerceIn(ps, pe)
                        sendProgress("📥 ${downloaded/1_048_576}MB${if(total>0) "/${total/1_048_576}MB" else ""}", p)
                    }
                }
            }}
            if (dest.length() < 512) { dest.delete(); throw Exception("File too small — server error") }
        }
    }

    private fun extractTarGz(tarFile: File, destDir: File) {
        TarArchiveInputStream(GzipCompressorInputStream(BufferedInputStream(tarFile.inputStream()))).use { tar ->
            var entry = tar.nextEntry
            while (entry != null) {
                if (isSetupCancelled.get()) throw Exception("Extraction cancelled")
                if (!tar.canReadEntryData(entry)) { entry = tar.nextEntry; continue }
                val target = File(destDir, entry.name.removePrefix("./"))
                if (!target.canonicalPath.startsWith(destDir.canonicalPath)) { entry = tar.nextEntry; continue }
                when {
                    entry.isDirectory -> target.mkdirs()
                    entry.isSymbolicLink -> {
                        try {
                            val tp = target.toPath(); val lp = java.nio.file.Paths.get(entry.linkName)
                            if (java.nio.file.Files.exists(tp, java.nio.file.LinkOption.NOFOLLOW_LINKS)) java.nio.file.Files.delete(tp)
                            target.parentFile?.mkdirs(); java.nio.file.Files.createSymbolicLink(tp, lp)
                        } catch (_: Exception) {
                            try { val ls = File(destDir, entry.linkName); if (ls.exists() && !ls.isDirectory) { target.parentFile?.mkdirs(); ls.copyTo(target, true) } } catch (_: Exception) {}
                        }
                    }
                    else -> {
                        target.parentFile?.mkdirs()
                        FileOutputStream(target).use { tar.copyTo(it) }
                        if (entry.mode and 0b001001001 != 0) target.setExecutable(true, false)
                    }
                }
                entry = tar.nextEntry
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        currentProcess?.destroyForcibly()
        executor.shutdown()
    }
}
