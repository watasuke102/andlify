package com.andlify.example

import android.os.ParcelFileDescriptor
import com.andlify.library.ChrootNative
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class ChrootSession(
    private val rootfsPath: String,
    private val commandPath: String,
    private val onOutput: (line: String, isStderr: Boolean) -> Unit,
    private val onSessionEnded: () -> Unit,
) {
    @Volatile
    private var pid: Int = 0

    private var stdinWriter: OutputStream? = null
    private var stdoutReader: InputStream? = null
    private var stderrReader: InputStream? = null

    private val streamsClosed = AtomicBoolean(false)
    private val endedNotified = AtomicBoolean(false)
    private val activeReaders = AtomicInteger(0)

    fun start(): Boolean {
        if (pid > 0) {
            return false
        }

        return try {
            val stdinPipe = ParcelFileDescriptor.createPipe()
            val stdoutPipe = ParcelFileDescriptor.createPipe()
            val stderrPipe = ParcelFileDescriptor.createPipe()

            val newPid = ChrootNative.start_chroot(
                extractDstPath = rootfsPath,
                commandPathInRootfs = commandPath,
                stdinFd = stdinPipe[0].fd,
                stdoutFd = stdoutPipe[1].fd,
                stderrFd = stderrPipe[1].fd,
            )
            if (newPid <= 0) {
                onOutput("start_chroot failed: $newPid", true)
                stdinPipe[0].close()
                stdinPipe[1].close()
                stdoutPipe[0].close()
                stdoutPipe[1].close()
                stderrPipe[0].close()
                stderrPipe[1].close()
                return false
            }

            pid = newPid
            stdinPipe[0].close()
            stdoutPipe[1].close()
            stderrPipe[1].close()

            stdinWriter = ParcelFileDescriptor.AutoCloseOutputStream(stdinPipe[1])
            stdoutReader = ParcelFileDescriptor.AutoCloseInputStream(stdoutPipe[0])
            stderrReader = ParcelFileDescriptor.AutoCloseInputStream(stderrPipe[0])

            startReader(stdoutReader, false, "stdout")
            startReader(stderrReader, true, "stderr")
            true
        } catch (e: IOException) {
            onOutput("Failed to create session pipes: ${e.message}", true)
            false
        }
    }

    fun sendLine(line: String): Boolean {
        val writer = stdinWriter ?: return false
        return try {
            writer.write(line.toByteArray(StandardCharsets.UTF_8))
            writer.write('\n'.code)
            writer.flush()
            true
        } catch (e: IOException) {
            onOutput("Failed to write stdin: ${e.message}", true)
            false
        }
    }

    fun stop() {
        val currentPid = pid
        if (currentPid > 0) {
            ChrootNative.stop_chroot(currentPid)
            pid = 0
        }
        closeAllStreams()
        notifyEnded()
    }

    private fun startReader(stream: InputStream?, isStderr: Boolean, threadSuffix: String) {
        if (stream == null) {
            return
        }
        activeReaders.incrementAndGet()
        Thread(
            {
                try {
                    BufferedReader(InputStreamReader(stream, StandardCharsets.UTF_8)).use { reader ->
                        while (true) {
                            val line = reader.readLine() ?: break
                            onOutput(line, isStderr)
                        }
                    }
                } catch (e: IOException) {
                    onOutput("Reader error ($threadSuffix): ${e.message}", true)
                } finally {
                    if (activeReaders.decrementAndGet() == 0) {
                        pid = 0
                        closeAllStreams()
                        notifyEnded()
                    }
                }
            },
            "andlify-$threadSuffix",
        ).start()
    }

    private fun closeAllStreams() {
        if (!streamsClosed.compareAndSet(false, true)) {
            return
        }
        try {
            stdinWriter?.close()
        } catch (e: IOException) {
            onOutput("Failed to close stdin writer: ${e.message}", true)
        }
        try {
            stdoutReader?.close()
        } catch (e: IOException) {
            onOutput("Failed to close stdout reader: ${e.message}", true)
        }
        try {
            stderrReader?.close()
        } catch (e: IOException) {
            onOutput("Failed to close stderr reader: ${e.message}", true)
        }

        stdinWriter = null
        stdoutReader = null
        stderrReader = null
    }

    private fun notifyEnded() {
        if (endedNotified.compareAndSet(false, true)) {
            onSessionEnded()
        }
    }
}
