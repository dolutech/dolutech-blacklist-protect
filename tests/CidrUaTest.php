<?php
/**
 * Testes do bloqueio CIDR e User-Agent.
 *
 * @package Dolutech_Blacklist_Protect
 */

use PHPUnit\Framework\TestCase;

class CidrUaTest extends TestCase {

    /** @dataProvider providerIpInCidr */
    public function testIpInCidr($ip, $cidr, $expected): void {
        $this->assertSame($expected, blwp_ip_in_cidr($ip, $cidr));
    }

    public static function providerIpInCidr(): array {
        return [
            // IPv4 dentro da faixa
            ['192.168.1.5', '192.168.1.0/24', true],
            ['192.168.1.255', '192.168.1.0/24', true],
            ['192.168.1.0', '192.168.1.0/24', true],
            // IPv4 fora da faixa
            ['192.168.2.5', '192.168.1.0/24', false],
            ['10.0.0.1', '192.168.1.0/24', false],
            ['8.8.8.8', '192.168.1.0/24', false],
            // Prefixos parciais
            ['192.168.1.77', '192.168.1.0/25', true],
            ['192.168.1.200', '192.168.1.0/25', false],
            // /32 exato
            ['203.0.113.10', '203.0.113.10/32', true],
            ['203.0.113.11', '203.0.113.10/32', false],
            // Sem prefixo = /32
            ['203.0.113.10', '203.0.113.10', true],
            // IPv6
            ['2001:db8::1', '2001:db8::/32', true],
            ['2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db8::/32', true],
            ['2001:db9::1', '2001:db8::/32', false],
            ['2001:db8::1', '2001:db8::1/128', true],
            ['2001:db8::2', '2001:db8::1/128', false],
            // Entradas inválidas
            ['invalid', '192.168.1.0/24', false],
            ['192.168.1.5', 'invalid', false],
            ['', '', false],
        ];
    }

    /** @dataProvider providerValidCidr */
    public function testIsValidCidr($cidr, $expected): void {
        $this->assertSame($expected, blwp_is_valid_cidr($cidr));
    }

    public static function providerValidCidr(): array {
        return [
            ['192.168.1.0/24', true],
            ['203.0.113.10/32', true],
            ['203.0.113.10', true],
            ['2001:db8::/32', true],
            ['192.168.1.0/33', false],
            ['2001:db8::/129', false],
            ['192.168.1.0/-1', false],
            ['not-an-ip/24', false],
            ['', false],
            ['1.2.3.4/abc', false],
        ];
    }

    public function testIsCidrBlocked(): void {
        $GLOBALS['blwp_test_options']['blwp_cidr_blocked'] = ['192.168.1.0/24', '2001:db8::/32'];

        $this->assertTrue(blwp_is_cidr_blocked('192.168.1.5'));
        $this->assertTrue(blwp_is_cidr_blocked('2001:db8::1'));
        $this->assertFalse(blwp_is_cidr_blocked('8.8.8.8'));
        $this->assertFalse(blwp_is_cidr_blocked('2001:db9::1'));

        // Lista vazia
        $GLOBALS['blwp_test_options']['blwp_cidr_blocked'] = [];
        $this->assertFalse(blwp_is_cidr_blocked('192.168.1.5'));
    }

    public function testIsUaBlocked(): void {
        $GLOBALS['blwp_test_options']['blwp_ua_block_enabled'] = 1;
        $GLOBALS['blwp_test_options']['blwp_ua_blocked'] = ['sqlmap', 'Nikto'];

        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; sqlmap/1.7)';
        $this->assertTrue(blwp_is_ua_blocked());

        // Case-insensitive
        $_SERVER['HTTP_USER_AGENT'] = 'nikto/2.1 scanner';
        $this->assertTrue(blwp_is_ua_blocked());

        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0';
        $this->assertFalse(blwp_is_ua_blocked());

        // Sem user-agent
        unset($_SERVER['HTTP_USER_AGENT']);
        $this->assertFalse(blwp_is_ua_blocked());

        // Desabilitado
        $GLOBALS['blwp_test_options']['blwp_ua_block_enabled'] = 0;
        $_SERVER['HTTP_USER_AGENT'] = 'sqlmap/1.7';
        $this->assertFalse(blwp_is_ua_blocked());

        unset($GLOBALS['blwp_test_options']['blwp_ua_block_enabled'], $GLOBALS['blwp_test_options']['blwp_ua_blocked']);
    }
}
