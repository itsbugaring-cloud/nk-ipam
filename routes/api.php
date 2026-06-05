<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\IpamController;

Route::post('/auth/login', [IpamController::class, 'login']);

// Authenticated routes
// We will use a simple middleware to check session token, or just rely on standard session for now since it's the same domain.
// Assuming stateful API for simple session usage, but we can also use Sanctum. The Rust version used simple custom token in DB or fixed environment variables.
// Let's use a custom middleware to replicate the Rust logic or just put it in the controller for simplicity if it's a single token.
Route::middleware('api.auth')->group(function () {
    Route::get('/health', [IpamController::class, 'health']);
    Route::get('/settings/mikrotik', [IpamController::class, 'getMikrotikSettings']);
    Route::post('/settings/mikrotik', [IpamController::class, 'updateMikrotikSettings']);
    Route::post('/bookmarks/import', [IpamController::class, 'importBookmarks']);
    Route::post('/routers/scan', [IpamController::class, 'scanRouter']);
    
    Route::post('/routers/{id}/rescan', [IpamController::class, 'rescanRouter']);
    Route::post('/routers/{id}/map-olt', [IpamController::class, 'updateRouterMapping']);
    Route::get('/routers/{id}/detail', [IpamController::class, 'getRouterDetail']);
    Route::get('/routers/{id}/wireguard', [IpamController::class, 'getRouterWireguard']);
    Route::get('/routers/export.csv', [IpamController::class, 'exportExplorerCsv']);
    
    Route::get('/olts', [IpamController::class, 'listOlts']);
    Route::post('/olts', [IpamController::class, 'createOlt']);
    
    Route::get('/explorer', [IpamController::class, 'listExplorer']);
    Route::get('/audit-logs', [IpamController::class, 'listAuditLogs']);
    
    Route::get('/subnets/utilization', [IpamController::class, 'getSubnetUtilization']);
    Route::get('/subnets/suggestions', [IpamController::class, 'getSubnetSuggestions']);
    Route::get('/subnets', [IpamController::class, 'listSubnets']);
    Route::post('/subnets', [IpamController::class, 'createSubnet']);
    Route::put('/subnets/{id}', [IpamController::class, 'updateSubnet']);
    Route::delete('/subnets/{id}', [IpamController::class, 'deleteSubnet']);
});
