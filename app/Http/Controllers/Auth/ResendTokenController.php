<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

use Auth;
use Validator;
use App\Jobs\SendVerificationEmail;

class ResendTokenController extends Controller
{
    public function index(Request $request)
    {
        if (Auth::check() && Auth::user()->verified == 1) {
            $request->session()->flash('status', 'You are already confirmed');
            return redirect('/');
        }

        if ($request->isMethod('post')) {
            $this->validator($request->only('email'))->validate();
            $user = User::where('email',$request->email)->first();
            if (1 == $user->verified) {
                $request->session()->flash('status', 'You are already confirmed');
                return back();
            }
            $user->email_token = str_random(64);
            if($user->save()){
                $request->session()->flash('status', 'An email is resend.');
                dispatch(new SendVerificationEmail($user));
                return redirect()->route('login');
            }
        } else {
            return view('auth.emailconfirm_resend');
        }
    }

    protected function validator(array $data)
    {
        return Validator::make($data, [
            'email' => 'required|string|email|max:255',
        ]);
    }
}
