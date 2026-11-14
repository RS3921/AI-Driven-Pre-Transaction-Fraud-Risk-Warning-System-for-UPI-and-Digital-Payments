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
import com.upifraudguard.app.data.ApiTokenStore
import com.upifraudguard.app.data.BackendUrlStore
import com.upifraudguard.app.data.LocalProfileStore
import com.upifraudguard.app.data.RiskRepository
import com.upifraudguard.app.ui.CheckViewModel
import com.upifraudguard.app.ui.CheckViewModelFactory
import com.upifraudguard.app.ui.screens.AccountScreen
import com.upifraudguard.app.ui.screens.MainTab
import com.upifraudguard.app.ui.screens.MainTabContainer
import com.upifraudguard.app.ui.screens.OnboardingScreen
import com.upifraudguard.app.ui.screens.QrScanScreen
import com.upifraudguard.app.ui.screens.ResultScreen
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
    const val ONBOARDING = "onboarding"
    const val MAIN = "main"
    const val SCAN = "scan"
    const val RESULT = "result"
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
        !LocalProfileStore.hasProfile(context) -> Routes.ACCOUNT
        !LocalProfileStore.hasCompletedOnboarding(context) -> Routes.ONBOARDING
        else -> Routes.MAIN
    }

    val initialTab = if (openHistory) MainTab.HISTORY else MainTab.HOME

    NavHost(navController = navController, startDestination = startDestination) {
        composable(Routes.ACCOUNT) {
            AccountScreen(onAccountCreated = {
                navController.navigate(Routes.ONBOARDING) {
                    popUpTo(Routes.ACCOUNT) { inclusive = true }
                    launchSingleTop = true
                }
            })
        }
        composable(Routes.ONBOARDING) {
            OnboardingScreen(onCompleted = {
                navController.navigate(Routes.MAIN) {
                    popUpTo(Routes.ONBOARDING) { inclusive = true }
                    launchSingleTop = true
                }
            })
        }
        composable(Routes.MAIN) {
            MainTabContainer(
                viewModel = viewModel,
                initialTab = initialTab,
                selectedHistoryMessage = selectedHistoryMessage,
                onOpenScanScreen = { navController.navigate(Routes.SCAN) },
                onOpenResultScreen = { navController.navigate(Routes.RESULT) },
                onLoggedOut = {
                    navController.navigate(Routes.ACCOUNT) {
                        popUpTo(0) { inclusive = true }
                        launchSingleTop = true
                    }
                },
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
            ResultScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() },
            )
        }
    }
}
