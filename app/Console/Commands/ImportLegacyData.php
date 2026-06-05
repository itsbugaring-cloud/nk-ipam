<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Crypt;

class ImportLegacyData extends Command
{
    protected $signature = 'ipam:import-legacy {db_path} {rust_crypto_key}';
    protected $description = 'Import legacy data from Rust SQLite database';

    public function handle()
    {
        $dbPath = $this->argument('db_path');
        $cryptoKey = $this->argument('rust_crypto_key');

        if (!file_exists($dbPath)) {
            $this->error("Database file not found: {$dbPath}");
            return 1;
        }

        $this->info("Connecting to legacy database...");
        config(['database.connections.legacy' => [
            'driver' => 'sqlite',
            'url' => env('DATABASE_URL'),
            'database' => $dbPath,
            'prefix' => '',
            'foreign_key_constraints' => env('DB_FOREIGN_KEYS', true),
        ]]);

        $legacyDb = DB::connection('legacy');

        $this->info("Importing OLTs...");
        $olts = $legacyDb->table('olts')->get();
        foreach ($olts as $olt) {
            DB::table('olts')->updateOrInsert(['id' => $olt->id], (array) $olt);
        }

        $this->info("Importing Subnets...");
        $subnets = $legacyDb->table('subnets')->get();
        foreach ($subnets as $subnet) {
            DB::table('subnets')->updateOrInsert(['id' => $subnet->id], (array) $subnet);
        }

        $this->info("Importing Routers...");
        $routers = $legacyDb->table('routers')->get();
        foreach ($routers as $router) {
            $data = (array) $router;
            if (!empty($data['auth_password'])) {
                $data['auth_password'] = Crypt::encryptString($this->decryptRustAesGcm($data['auth_password'], $cryptoKey));
            }
            DB::table('routers')->updateOrInsert(['id' => $router->id], $data);
        }

        $tables = ['ip_pools', 'router_addresses', 'router_routes', 'wireguard_interfaces', 'wireguard_peers', 'audit_logs'];
        foreach ($tables as $table) {
            $this->info("Importing {$table}...");
            $rows = $legacyDb->table($table)->get();
            foreach ($rows as $row) {
                DB::table($table)->updateOrInsert(['id' => $row->id], (array) $row);
            }
        }

        $this->info("Legacy data imported successfully.");
        return 0;
    }

    private function decryptRustAesGcm($encoded, $secret)
    {
        $payload = base64_decode($encoded);
        if (strlen($payload) < 13) return '';

        $nonce = substr($payload, 0, 12);
        $ciphertextAndTag = substr($payload, 12);
        
        $ciphertext = substr($ciphertextAndTag, 0, -16);
        $tag = substr($ciphertextAndTag, -16);

        $key = hash('sha256', $secret, true);

        return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    }
}
