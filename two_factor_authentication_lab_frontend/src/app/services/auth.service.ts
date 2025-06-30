import { Injectable } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { tap, catchError, map, filter } from 'rxjs/operators';

interface RegisterResponse {
  success: boolean;
  message: string;
  data: {
    succeeded: boolean;
    errors: string[];
  };
  response: ErrorDetails;
}

interface RegisterRequest {
  username: string;
  password: string;
  email: string;
  name: string;
}

interface LoginRequest {
  usernameOrEmail: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  data: any;
  error: ErrorDetails | null;
  authenticationStatus?: string;
}

interface Setup2FAResponse {
  success: boolean;
  message: string;
  data?: {
    qrImage: string;
    token: string;
    issuer: string;
    email: string;
  };
  error?: any;
}

interface UsernameCheckResponse {
  success: boolean;
  message: string;
  data: boolean;
  error: string | null;
  authenticationStatus: string | null;
}

export interface Login2FAResponse {
  authenticationStatus: string;
  success: boolean;
  message: string;
  data?: UserData | null;
  error?: ErrorDetails | null;
  token?: string;
}

export interface UserData {
  id: string;
  username: string;
  name: string;
  email: string;
  phone: string | null;
  address: string | null;
  twoFactorEnabled: boolean;
}

export interface ErrorDetails {
  code: string;
  messages: string[];
}

export interface WeatherForecast {
  date: string;
  temperatureC: number;
  temperatureF: number;
  summary: string;
}

export interface LogoutResponse {
  success: boolean;
  message: string;
  data: boolean;
  error?: ErrorDetails | null;
  token?: string | '';
}

export interface Verify2FAResponse {
  authenticationStatus: string;
  success: boolean;
  message: string;
  data?: {
    userId: string;
    backupCodes: string[];
  } | null;
  error?: {
    code: string;
    messages: string[];
  } | null;
  token?: string;
}

interface AuthenticationStatusDTO {
  isAuthenticated: boolean;
  requiresTwoFactor: boolean;
  requiresTwoFactorSetup: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl = 'https://localhost:7226';

  constructor(private http: HttpClient) {}

  login(data: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/Auth/login`, data, { withCredentials: true })
  }

  register(data: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.baseUrl}/Auth/register`, data);
  }

  checkUsername(username: string): Observable<HttpResponse<UsernameCheckResponse>> {
    return this.http.post<UsernameCheckResponse>(`${this.baseUrl}/Auth/username-exists?username=${username}`, {}, { observe: 'response' });
  }

  setup2fa(): Observable<Setup2FAResponse> {
    return this.http.post<Setup2FAResponse>(`${this.baseUrl}/Auth/setup2fa`, {}, { withCredentials: true })
  }

  verify2fa(code: string): Observable<Verify2FAResponse> {
    return this.http.post<Verify2FAResponse>(`${this.baseUrl}/Auth/verify2fa?code=${code}`, {}, { withCredentials: true })
  }

  login2fa(code: string): Observable<Login2FAResponse> {
    return this.http.post<Login2FAResponse>(`${this.baseUrl}/Auth/login2fa?code=${code}`, {}, { withCredentials: true })
  }

  login2faBackupCode(backupCode: string): Observable<Login2FAResponse> {
    return this.http.post<Login2FAResponse>(`${this.baseUrl}/Auth/login2fabackupcode?code=${backupCode}`, {}, { withCredentials: true });
  }

  logout(): Observable<LogoutResponse> {
    return this.http.post<LogoutResponse>(`${this.baseUrl}/Auth/logout`, {}, { withCredentials: true });
  }

  getWeatherForecast(): Observable<WeatherForecast[]> {
    return this.http.get<WeatherForecast[]>(`${this.baseUrl}/WeatherForecast`, { withCredentials: true });
  }

  isLoggedIn(): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/Auth/isloggedin`, {}, { withCredentials: true });
  }

}


