package eu.kylian.kc.krb;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkMatcherTest {

    @Test
    void blankMatchesEveryone() {
        for (String raw : new String[]{null, "", "   ", "\n"}) {
            NetworkMatcher m = NetworkMatcher.parse(raw);
            assertTrue(m.isUnrestricted());
            assertTrue(m.matches("203.0.113.9"));
            assertTrue(m.matches(null));
        }
    }

    @Test
    void matchesIpv4Prefix() {
        NetworkMatcher m = NetworkMatcher.parse("10.0.0.0/8, 192.168.1.0/24");
        assertFalse(m.isUnrestricted());
        assertTrue(m.matches("10.200.3.4"));
        assertTrue(m.matches("192.168.1.77"));
        assertFalse(m.matches("192.168.2.1"));
        assertFalse(m.matches("11.0.0.1"));
    }

    @Test
    void matchesIpv6Prefix() {
        NetworkMatcher m = NetworkMatcher.parse("fd00::/8, 2001:db8:abcd::/48");
        assertTrue(m.matches("fd12:3456::1"));
        assertTrue(m.matches("2001:db8:abcd:1::5"));
        assertFalse(m.matches("2001:db8:abce::1"));
        assertFalse(m.matches("2a07:8d80::1"));
    }

    @Test
    void handlesPrefixNotOnByteBoundary() {
        NetworkMatcher m = NetworkMatcher.parse("172.16.0.0/12");
        assertTrue(m.matches("172.31.255.255"));
        assertFalse(m.matches("172.32.0.1"));
    }

    @Test
    void ipv4AndIpv6DoNotMix() {
        assertFalse(NetworkMatcher.parse("10.0.0.0/8").matches("fd00::1"));
        assertFalse(NetworkMatcher.parse("fd00::/8").matches("10.0.0.1"));
    }

    @Test
    void ipv4MappedIpv6MatchesIpv4Prefix() {
        assertTrue(NetworkMatcher.parse("10.0.0.0/8").matches("::ffff:10.1.2.3"));
    }

    @Test
    void entryWithoutPrefixIsSingleHost() {
        NetworkMatcher m = NetworkMatcher.parse("192.0.2.5 2001:db8::1");
        assertTrue(m.matches("192.0.2.5"));
        assertFalse(m.matches("192.0.2.6"));
        assertTrue(m.matches("2001:db8::1"));
        assertFalse(m.matches("2001:db8::2"));
    }

    @Test
    void acceptsCommaSemicolonAndNewlineSeparators() {
        NetworkMatcher m = NetworkMatcher.parse("10.0.0.0/8;192.168.0.0/16\nfd00::/8,\r\n172.16.0.0/12");
        assertTrue(m.matches("10.1.1.1"));
        assertTrue(m.matches("192.168.9.9"));
        assertTrue(m.matches("fd00::9"));
        assertTrue(m.matches("172.20.0.1"));
    }

    @Test
    void skipsInvalidEntriesAndKeepsValidOnes() {
        NetworkMatcher m = NetworkMatcher.parse("nonsense, 10.0.0.0/33, 10.0.0.0/x, example.com, 192.168.0.0/16");
        assertFalse(m.isUnrestricted());
        assertTrue(m.matches("192.168.4.4"));
        assertFalse(m.matches("10.0.0.1"));
    }

    @Test
    void allInvalidMatchesNobody() {
        NetworkMatcher m = NetworkMatcher.parse("nonsense, 300.1.1.1/8");
        assertFalse(m.isUnrestricted());
        assertFalse(m.matches("10.0.0.1"));
    }

    @Test
    void invalidOrMissingClientIpDoesNotMatch() {
        NetworkMatcher m = NetworkMatcher.parse("0.0.0.0/0");
        assertFalse(m.matches(null));
        assertFalse(m.matches("not-an-ip"));
        assertFalse(m.matches(""));
    }

    @Test
    void zoneIdIsIgnored() {
        assertTrue(NetworkMatcher.parse("fe80::/10").matches("fe80::1%eth0"));
    }
}
