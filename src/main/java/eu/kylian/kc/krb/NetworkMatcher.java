package eu.kylian.kc.krb;

import org.jboss.logging.Logger;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Matches a client IP against a list of CIDR prefixes (IPv4 and IPv6).
 *
 * <p>A blank list matches every address. A non-blank list with no valid entry matches nothing.
 * Invalid entries are logged and skipped. Host names are never resolved.
 */
final class NetworkMatcher {
    private static final Logger LOG = Logger.getLogger(NetworkMatcher.class);
    private static final Pattern SEPARATORS = Pattern.compile("[,;\\s]+");
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private record Cidr(byte[] network, int prefix) {
        boolean contains(byte[] addr) {
            if (addr.length != network.length) return false;
            int fullBytes = prefix / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (addr[i] != network[i]) return false;
            }
            int rest = prefix % 8;
            if (rest == 0) return true;
            int mask = (0xFF << (8 - rest)) & 0xFF;
            return (addr[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }

    private final boolean matchAll;
    private final List<Cidr> prefixes;

    private NetworkMatcher(boolean matchAll, List<Cidr> prefixes) {
        this.matchAll = matchAll;
        this.prefixes = prefixes;
    }

    static NetworkMatcher parse(String raw) {
        if (raw == null || raw.isBlank()) return new NetworkMatcher(true, List.of());

        List<Cidr> list = new ArrayList<>();
        for (String entry : SEPARATORS.split(raw.trim())) {
            if (entry.isEmpty()) continue;
            Cidr c = parseEntry(entry);
            if (c == null) {
                LOG.warnf("krb-probe: ignoring invalid internal network entry '%s'", entry);
            } else {
                list.add(c);
            }
        }
        if (list.isEmpty()) {
            LOG.warn("krb-probe: internal networks are set but none is valid; no client will match");
        }
        return new NetworkMatcher(false, List.copyOf(list));
    }

    boolean isUnrestricted() {
        return matchAll;
    }

    boolean matches(String clientIp) {
        if (matchAll) return true;
        byte[] addr = toBytes(clientIp);
        if (addr == null) return false;
        for (Cidr c : prefixes) {
            if (c.contains(addr)) return true;
        }
        return false;
    }

    private static Cidr parseEntry(String entry) {
        String host = entry;
        Integer prefix = null;
        int slash = entry.indexOf('/');
        if (slash >= 0) {
            host = entry.substring(0, slash);
            try {
                prefix = Integer.parseInt(entry.substring(slash + 1));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        byte[] addr = toBytes(host);
        if (addr == null) return null;
        int max = addr.length * 8;
        if (prefix == null) prefix = max;
        if (prefix < 0 || prefix > max) return null;
        return new Cidr(addr, prefix);
    }

    /** Parses an IP literal. Returns null for anything else, so no DNS lookup can happen. */
    private static byte[] toBytes(String ip) {
        if (ip == null) return null;
        String s = ip.trim();
        int zone = s.indexOf('%');
        if (zone >= 0) s = s.substring(0, zone);
        if (!IPV4.matcher(s).matches() && s.indexOf(':') < 0) return null;
        try {
            // For IP literals this does not query DNS. An IPv4-mapped IPv6 address
            // (::ffff:a.b.c.d) is returned as an Inet4Address, so it matches IPv4 prefixes.
            return InetAddress.getByName(s).getAddress();
        } catch (Exception e) {
            return null;
        }
    }
}
