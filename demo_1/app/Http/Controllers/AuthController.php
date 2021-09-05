<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use JWTAuth;

class AuthController extends Controller
{
    //
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        $credentials = $request->only('email', 'password');

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    public function register(Request $request){

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(),400);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password'=> bcrypt($request->password)]
        ));

        return response()->json(['message'=> "User Successfully Register", 'data'=>$user ], 201);
    }

    public function logout(){
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }
    
    public function userProfile() {
        return response()->json(auth()->user());
    }

    protected function createNewToken($token){

       // $token =JWTAuth::toUser($request->input('token'));
        return response()->json([
            'token_type'=> 'beare',
            'expires_in' => auth('api')->factory()->getTTL()*60,
            'data'=>[
                'token'=> $token,
                'user'=>  Auth::user(),
            ],
        ], 200, );
    }
    public function getUser(){
        $user = auth('api')->user();
        return response()->json(['user'=>$user], 201);
    }
}
