package com.secretbroker.mobile.otp

import android.content.Context
import androidx.core.content.edit

object SimBindings {
    fun bind(context: Context, subscriptionId: Int, opaqueBinding: String) {
        require(subscriptionId >= 0)
        require(opaqueBinding.matches(Regex("[a-z0-9][a-z0-9._:-]{0,127}")))
        context.getSharedPreferences("sim-bindings", Context.MODE_PRIVATE).edit {
            putString(subscriptionId.toString(), opaqueBinding)
        }
    }

    fun resolve(context: Context, subscriptionId: Int): String? {
        if (subscriptionId < 0) return null
        return context.getSharedPreferences("sim-bindings", Context.MODE_PRIVATE)
            .getString(subscriptionId.toString(), null)
    }
}
