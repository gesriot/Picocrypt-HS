package io.github.picocrypt_ng.picocrypt_ng.testutils

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.rules.TestWatcher
import org.junit.runner.Description

@OptIn(ExperimentalCoroutinesApi::class)
class MainDispatcherRule(
    private val dispatcherFactory: () -> TestDispatcher = { StandardTestDispatcher() },
) : TestWatcher() {
    private var _testDispatcher: TestDispatcher? = null
    val testDispatcher: TestDispatcher
        get() = _testDispatcher ?: error("MainDispatcherRule has not started yet")

    override fun starting(description: Description) {
        _testDispatcher = dispatcherFactory()
        Dispatchers.setMain(testDispatcher)
    }

    override fun finished(description: Description) {
        Dispatchers.resetMain()
        _testDispatcher = null
    }
}
