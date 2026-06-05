<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Olt;
use App\Models\Router;
use App\Models\AuditLog;
use App\Models\Subnet;

class IpamController extends Controller
{
    public function health() {
        return response()->json(['status' => 'ok', 'message' => 'Netking IPAM API (Laravel) is running']);
    }

    public function login(Request $request) {
        $username = $request->input('username');
        $password = $request->input('password');
        
        if ($username === 'userapi' && $password === 'NETKING') {
            return response()->json(['token' => 'dummy-token']);
        }
        return response()->json(['error' => 'Invalid credentials'], 401);
    }

    public function listExplorer(Request $request) {
        $routers = Router::with(['olt'])->get();
        return response()->json($routers);
    }

    public function listOlts(Request $request) {
        $olts = Olt::all();
        return response()->json($olts);
    }

    public function createOlt(Request $request) {
        $request->validate([
            'name' => 'required|string',
            'ip_address' => 'required|string',
        ]);
        
        $olt = Olt::create([
            'name' => $request->name,
            'ip_address' => $request->ip_address,
        ]);

        AuditLog::create([
            'actor' => 'api',
            'action' => 'create_olt',
            'target_type' => 'olt',
            'target_id' => $olt->id,
            'detail' => "Manually added OLT: {$olt->name} ({$olt->ip_address})",
            'created_at' => now(),
        ]);

        return response()->json($olt);
    }

    public function getRouterDetail($id) {
        $router = Router::with(['pools', 'addresses', 'routes', 'wireguardInterfaces', 'wireguardPeers'])->findOrFail($id);
        return response()->json($router);
    }

    public function listAuditLogs() {
        return response()->json(AuditLog::orderBy('id', 'desc')->limit(100)->get());
    }

    public function listSubnets() {
        return response()->json(Subnet::all());
    }

    // Mikrotik operations (Mocked for brevity, will be implemented fully later)
    public function scanRouter(Request $request) {
        return response()->json(['status' => 'success', 'message' => 'Router scanned via Laravel API']);
    }

    public function updateRouterMapping(Request $request, $id) {
        $router = Router::findOrFail($id);
        $router->mapped_olt_id = $request->input('mapped_olt_id');
        $router->save();
        return response()->json($router);
    }
}
