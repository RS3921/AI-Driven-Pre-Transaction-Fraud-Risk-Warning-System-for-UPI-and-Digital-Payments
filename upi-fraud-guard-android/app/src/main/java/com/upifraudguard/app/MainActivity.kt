package com.upifraudguard.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.upifraudguard.app.data.BackendUrlStore
import com.upifraudguard.app.data.ApiTokenStore
import com.upifraudguard.app.data.RiskRepository
import com.upifraudguard.app.ui.CheckViewModel
import com.upifraudguard.app.ui.CheckViewModelFactory
import com.upifraudguard.app.data.LocalProfileStore
import com.upifraudguard.app.ui.screens.AccountScreen
import com.upifraudguard.app.ui.screens.CheckScreen
import com.upifraudguard.app.ui.screens.HistoryScreen
import com.upifraudguard.app.ui.screens.QrScanScreen
import com.upifraudguard.app.ui.screens.ResultScreen
import com.upifraudguard.app.ui.screens.SettingsScreen
import com.upifraudguard.app.ui.theme.UpiFraudGuardTheme

class MainActivity : ComponentActivity() {
    private val viewModel: CheckViewModel by viewModels {
        CheckViewModelFactory(
            RiskRepository(
                { BackendUrlStore.get(applicationContext) },
                { ApiTokenStore.get(applicationContext) },
            ),
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            UpiFraudGuardTheme {
                UpiFraudGuardApp(
                    viewModel,
                    intent.getBooleanExtra(EXTRA_OPEN_HISTORY, false),
                    intent.getStringExtra(EXTRA_HISTORY_MESSAGE),
                )
            }
        }
    }

    companion object {
        const val EXTRA_OPEN_HISTORY = "open_history"
        const val EXTRA_HISTORY_MESSAGE = "history_message"
    }
}

private object Routes {
    const val ACCOUNT = "account"
    const val CHECK = "check"
    const val SCAN = "scan"
    const val RESULT = "result"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
}

@Composable
fun UpiFraudGuardApp(
    viewModel: CheckViewModel,
    openHistory: Boolean = false,
    selectedHistoryMessage: String? = null,
) {
    val navController = rememberNavController()
    val context = LocalContext.current
    val startDestination = when {
        openHistory -> Routes.HISTORY
        LocalProfileStore.hasProfile(context) -> Routes.CHECK
        else -> Routes.ACCOUNT
    }

    NavHost(navController = navController, startDestination = startDestination) {
        composable(Routes.ACCOUNT) {
            AccountScreen(onAccountCreated = {
                navController.navigate(Routes.CHECK) {
                    popUpTo(Routes.ACCOUNT) { inclusive = true }
                    launchSingleTop = true
                }
            })
        }
        composable(Routes.CHECK) {
            CheckScreen(
                viewModel = viewModel,
                onScanQr = { navController.navigate(Routes.SCAN) },
                onOpenHistory = { navController.navigate(Routes.HISTORY) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
                onResult = { navController.navigate(Routes.RESULT) },
            )
        }
        composable(Routes.SCAN) {
            QrScanScreen(
                onQrDetected = { payload ->
                    navController.popBackStack()
                    viewModel.runCheck(
                        message = "",
                        urlOrQr = payload,
                        amountText = "",
                        recipient = "",
                        isNewRecipient = null,
                    )
                },
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.RESULT) {
            ResultScreen(viewModel = viewModel, onBack = { navController.popBackStack(Routes.CHECK, false) })
        }
        composable(Routes.HISTORY) {
            HistoryScreen(viewModel = viewModel, selectedMessage = selectedHistoryMessage)
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(onBack = { navController.popBackStack() })
        }
    }
}
