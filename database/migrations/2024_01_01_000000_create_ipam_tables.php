<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('subnets', function (Blueprint $table) {
            $table->id();
            $table->string('network_address')->unique();
            $table->integer('prefix_length');
            $table->string('name')->nullable();
            $table->string('description')->nullable();
            $table->string('vlan_id')->nullable();
            $table->string('location')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('olts', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('ip_address')->unique();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('routers', function (Blueprint $table) {
            $table->id();
            $table->string('device_name');
            $table->string('wireguard_ip')->unique();
            $table->string('auth_username')->nullable();
            $table->string('auth_password')->nullable();
            $table->string('auth_source')->nullable();
            $table->string('connection_status');
            $table->string('last_error')->nullable();
            $table->string('last_scanned_at')->nullable();
            $table->foreignId('mapped_olt_id')->nullable()->constrained('olts')->nullOnDelete();
            $table->boolean('is_online')->nullable();
            $table->string('last_ping_at')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('ip_pools', function (Blueprint $table) {
            $table->id();
            $table->foreignId('router_id')->constrained('routers')->cascadeOnDelete();
            $table->string('pool_name');
            $table->string('ranges');
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
            $table->unique(['router_id', 'pool_name']);
        });

        Schema::create('router_addresses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('router_id')->constrained('routers')->cascadeOnDelete();
            $table->string('address');
            $table->string('network');
            $table->string('interface');
            $table->boolean('disabled')->default(false);
            $table->string('comment')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('router_routes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('router_id')->constrained('routers')->cascadeOnDelete();
            $table->string('dst_address');
            $table->string('gateway');
            $table->string('distance')->nullable();
            $table->boolean('disabled')->default(false);
            $table->string('comment')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('wireguard_interfaces', function (Blueprint $table) {
            $table->id();
            $table->foreignId('router_id')->constrained('routers')->cascadeOnDelete();
            $table->string('name');
            $table->string('listen_port')->nullable();
            $table->string('public_key')->nullable();
            $table->boolean('disabled')->default(false);
            $table->string('comment')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
            $table->unique(['router_id', 'name']);
        });

        Schema::create('wireguard_peers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('router_id')->constrained('routers')->cascadeOnDelete();
            $table->string('interface_name');
            $table->string('public_key');
            $table->string('allowed_address');
            $table->string('endpoint_address')->nullable();
            $table->string('endpoint_port')->nullable();
            $table->boolean('disabled')->default(false);
            $table->string('comment')->nullable();
            $table->string('created_at')->nullable();
            $table->string('updated_at')->nullable();
        });

        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->string('actor');
            $table->string('action');
            $table->string('target_type');
            $table->string('target_id')->nullable();
            $table->string('detail');
            $table->string('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('wireguard_peers');
        Schema::dropIfExists('wireguard_interfaces');
        Schema::dropIfExists('router_routes');
        Schema::dropIfExists('router_addresses');
        Schema::dropIfExists('ip_pools');
        Schema::dropIfExists('routers');
        Schema::dropIfExists('olts');
        Schema::dropIfExists('subnets');
    }
};
