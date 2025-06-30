import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-setup2fa',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './setup2fa.component.html',
  styleUrl: './setup2fa.component.scss'
})
export class Setup2faComponent implements OnInit {
  qrImage: string | null = null;
  token: string | null = null;
  issuer: string | null = null;
  email: string | null = null;
  setupError: string = '';

  code: string = '';
  backupCodes: string[] | undefined = [];
  message: string = '';

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit() {
      this.authService.setup2fa().subscribe({
        next: (response) => {
          if (response.success && response.data) {
            this.qrImage = response.data.qrImage;
            this.token = response.data.token;
            this.issuer = response.data.issuer;
            this.email = response.data.email;
          } else {
            this.setupError = response.message || 'Failed to generate 2FA setup code. Please try again.';
          }
        },
        error: (err) => {
          this.setupError = 'An error occurred during 2FA setup.';
          console.error('2FA setup error:', err);
        },
      });

        this.authService.isLoggedIn().subscribe((res) => {
          if (res.data.isAuthenticated) {
            this.router.navigate(['/dashboard']);
          } else if (res.data.requiresTwoFactor) {
            this.router.navigate(['/login2fa']);
          } else if (res.data.requiresTwoFactorSetup) {
            // do nothing
          } else {
            this.router.navigate(['/login']);
          }
        })
    } 

    verifyCode(): void {
      this.authService.verify2fa(this.code).subscribe(
        (response) => {
          if (response.success) {
            this.message = response.message;
            this.backupCodes = response.data?.backupCodes;
          } else {
            this.message = response.error?.messages[0] || 'Verification failed. Please try again.';
          }
        },
        (error) => {
          this.message = 'Verification failed. Please try again.';
        }
      );
    }

    navigateToLogin(): void {
      this.router.navigate(['/login2fa']);
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
