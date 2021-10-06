/**
 * Brief explanation:
 * At the beginning of the program I take each IP in the badIPs list, I convert it into bits (as a string),
 * and then take only the network part of it, and add it to the badNetworks set. For example:
 * If the IP is "255.255.0.0/24" then we add "111111111111111100000000" to badNetworks (first 24 bits).
 * Then when we call isAllowed(), it takes the given IP and also converts it into bits as a string.
 * Then in a loop where X goes from 32 to 0 it checks if the first X bits of the IP exist in the badNetworks set.
 * For example:
 * If the incomingIP is "1.2.3.4", then it's bit representation is: "00000001000000100000001100000100" (we ignore
 * the dots). Then we check if this entire string exists in the badNetworks, if not we check only the first 31 bits,
 * then 30 bits etc. If we find a match we return false meaning it's a suspicious IP and isn't allowed. Otherwise
 * we return true.
 */

import java.util.*
import java.util.regex.Matcher
import java.util.regex.Pattern


val badIPs = listOf<String>(
    "1.2.3.4/4",
    "255.255.0.0/24",
    "10.0.0.0/24",
    "192.168.10.0/24",
    "192.168.10.0/20",
    "1.0.0.0/8"
)

var badNetowkrs: HashSet<String> = hashSetOf<String>()

/**
 * Takes an IP and a flag isCIDR.
 * If isCIDR is true, returns true if the IP is a valid CIDR notation.
 * If isCIDR is false, returns true if the IP is a valid IPv4 format.
 */
fun checkValidIPFormat(ip: String, isCIDR: Boolean) : Boolean {
    var patternRegex = ""
    if (isCIDR) {
        patternRegex = "^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))"
    } else {
        patternRegex = "^([0-9]{1,3}\\.){3}[0-9]{1,3}"
    }

    val pattern: Pattern = Pattern.compile(patternRegex)
    val matcher: Matcher = pattern.matcher(ip)
    if (matcher.matches()){
        return true
    }
    return false
}

/**
 * Takes an IP as string and returns a bit representation of the IP also as a string.
 */
fun getIPAsBits(ip: String) : String {
    val parts: List<String> = ip.split(".")
    var bits = ""
    for (part in parts){
        bits += java.lang.String.format("%8s", Integer.toBinaryString(part.toInt())).replace(' ', '0')
    }
    return bits
}

/**
 * Takes an ip in CIDR notation and returns only the network part of the ip,
 * represented in bits.
 */
fun getNetworkBits(ip: String) : String {

    // Validate the ip is in a valid format
    if (!checkValidIPFormat(ip, isCIDR = true)){
        println(ip + " is not a valid CIDR format")
        return ""
    }

    val parts: List<String> = ip.split("/")
    val ipAsBits = getIPAsBits(parts[0])
    val networkLength = parts[1].toInt()
    return ipAsBits.substring(0, networkLength)
}

/**
 * Returns false if a given IP belongs to any of the suspicious IP ranges,
 * and true otherwise.
 */
fun isAllowed(incomingIp: String) : Boolean {

    val ipAsBits = getIPAsBits(incomingIp)
    for (i in 32 downTo 0) {
        val networkBits = ipAsBits.substring(0, i)
        if (badNetowkrs.contains(networkBits)) {
            return false;
        }
    }
    return true
}

fun main(args: Array<String>) {

    // Create hash set of suspicious networks
    for (ip in badIPs) {
        val networkBits = getNetworkBits(ip)
        if (networkBits != "")
            badNetowkrs.add(networkBits)
    }

    // Check some example IP
    val exampleIp = "255.255.2.0"

    if (checkValidIPFormat(exampleIp, isCIDR = false)) {
        if (isAllowed(exampleIp)) {
            println("IP " + exampleIp + " is allowed")
        } else {
            println("IP " + exampleIp + " is suspicious")
        }
    }   else {
        println(exampleIp + " is not a valid IPv4 format")
    }
}