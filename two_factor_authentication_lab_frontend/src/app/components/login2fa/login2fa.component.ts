import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Login2FAResponse } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login2fa',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login2fa.component.html',
  styleUrl: './login2fa.component.scss'
})
export class Login2faComponent implements OnInit{
  code: string = '';
  message: string = '';
  isBackupCode: boolean = false;

  constructor(private authService: AuthService, private router: Router) {}

  toggleBackupCode() {
    this.isBackupCode = !this.isBackupCode;
    this.message = '';
  }

  onSubmit() {

    if (this.isBackupCode) {
      this.authService.login2faBackupCode(this.code).subscribe(
        response => this.handleResponse(response),
        err => this.message = err.error?.message || 'Failed to log in with backup code.'
      );
    } else {
      this.authService.login2fa(this.code).subscribe(
        response => this.handleResponse(response),
        err => this.message = err.error?.message || 'Failed to log in with 2FA code.'
      );
    }
  }

  handleResponse(response: Login2FAResponse) {
    if (response.success) {
      this.message = 'Login successful!';
      this.router.navigate(['/dashboard']);
    } else {
      this.message = response.error?.messages[0] || 'Login failed. Please try again.';
    }
  }

  ngOnInit(): void {
    this.authService.isLoggedIn().subscribe((res) => {
      console.log(res)
      if (res.data.isAuthenticated) {
        this.router.navigate(['/dashboard']);
      } else if (res.data.requiresTwoFactor) {
        // Do nothing
      } else if (res.data.requiresTwoFactorSetup) {
        this.router.navigate(['/setup2fa']);
      } else {
        this.router.navigate(['/login']);
      }
    })
  }

  logout(): void {
    this.authService.logout().subscribe(
      (response) => {
        if (response.success)
          this.router.navigate(['/login']);
      },
    );
  }
}
