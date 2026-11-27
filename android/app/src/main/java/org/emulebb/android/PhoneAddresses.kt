package org.emulebb.android

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler

/** Read-only addresses from Android's current network inventory. */
internal class PhoneAddresses(
    private val connectivity: ConnectivityManager,
    private val handler: Handler,
    private val render: (String) -> Unit,
) {
    private data class Connection(
        val capabilities: NetworkCapabilities? = null,
        val properties: LinkProperties? = null,
    )

    private val networks = mutableMapOf<Network, Connection>()
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        if (callback != null) return
        val listener = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (callback !== this) return
                networks[network] = (networks[network] ?: Connection()).copy(capabilities = caps)
                refresh()
            }

            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                if (callback !== this) return
                networks[network] = (networks[network] ?: Connection()).copy(properties = properties)
                refresh()
            }

            override fun onLost(network: Network) {
                if (callback !== this) return
                networks.remove(network)
                refresh()
            }
        }
        callback = listener
        connectivity.registerNetworkCallback(NetworkRequest.Builder().clearCapabilities().build(), listener, handler)
        refresh()
    }

    fun stop() {
        callback?.let(connectivity::unregisterNetworkCallback)
        callback = null
        networks.clear()
    }

    private fun refresh() {
        val addresses = networks.values.flatMap { (caps, properties) ->
            val label = when {
                caps == null -> properties?.interfaceName ?: "Network"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                else -> properties?.interfaceName ?: "Network"
            }
            properties?.linkAddresses.orEmpty().mapNotNull { link ->
                val ip = link.address
                ip.hostAddress?.takeUnless { ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isMulticastAddress }
                    ?.let { "$label  $it" }
            }
        }.distinct().sorted()
        render("LAN and interface addresses\n" + addresses.ifEmpty { listOf("None") }.joinToString("\n"))
    }
}
