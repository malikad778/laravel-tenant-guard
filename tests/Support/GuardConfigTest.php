<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Support;

use MalikAd\TenantGuard\Support\GuardConfig;
use PHPUnit\Framework\TestCase;

final class GuardConfigTest extends TestCase
{
    public function testDefaultConfigurationValues(): void
    {
        $config = new GuardConfig();

        self::assertContains('company_id', $config->tenantColumns);
        self::assertContains('users', $config->tenantTables);
        self::assertContains('migrations', $config->globalTables);
        self::assertContains('tenant', $config->tenantDisks);
        self::assertContains('tenant', $config->tenantCacheStores);
        self::assertTrue($config->isRuleEnabled('unscoped_database_query'));
    }

    public function testStrictAllTablesToggle(): void
    {
        $strictConfig = new GuardConfig(['strict_all_tables' => true]);
        $nonStrictConfig = new GuardConfig(['strict_all_tables' => false]);

        // Unlisted custom table
        self::assertTrue($strictConfig->isTenantTable('custom_unlisted_table'));
        self::assertFalse($nonStrictConfig->isTenantTable('custom_unlisted_table'));

        // Explicit global table
        self::assertFalse($strictConfig->isTenantTable('migrations'));
        self::assertFalse($nonStrictConfig->isTenantTable('migrations'));

        // Explicit tenant table
        self::assertTrue($strictConfig->isTenantTable('invoices'));
        self::assertTrue($nonStrictConfig->isTenantTable('invoices'));
    }

    public function testTenantDiskAndCacheStoreIdentification(): void
    {
        $config = new GuardConfig([
            'tenant_disks' => ['custom_tenant_disk'],
            'tenant_cache_stores' => ['custom_tenant_redis'],
        ]);

        self::assertTrue($config->isTenantDisk('custom_tenant_disk'));
        self::assertFalse($config->isTenantDisk('s3_public'));

        self::assertTrue($config->isTenantCacheStore('custom_tenant_redis'));
        self::assertFalse($config->isTenantCacheStore('file'));
    }
}
