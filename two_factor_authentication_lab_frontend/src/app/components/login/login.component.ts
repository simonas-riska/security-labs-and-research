import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit{
  loginForm: FormGroup;
  showPasswordField: boolean = false;
  loginError: string = '';

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
    this.loginForm = this.fb.group({
      usernameOrEmail: ['', Validators.required],
      password: [''],
    });
  }

  onSubmit(): void {
    if (!this.showPasswordField) {
      this.checkUsername();
    } else if (this.loginForm.valid) {
      this.performLogin();
    }
  }

  private checkUsername(): void {
    const username = this.loginForm.get('usernameOrEmail')?.value;
    console.log(username);
    this.authService.checkUsername(username).subscribe({
      next: (response) => {
        console.log(response.body)
        if (response.body?.data) {
          this.showPasswordField = true;
          this.loginForm.get('password')?.setValidators([Validators.required]);
          this.loginForm.get('password')?.updateValueAndValidity();
          this.loginError = '';
        } else {
          this.loginError = 'Username not found';
        }
      },
      error: (err) => {
        this.loginError = 'Error checking username. Please try again';
        console.log(err);
      },
    });
  }
  
  private performLogin(): void {
    this.authService.login(this.loginForm.value).subscribe({
      next: (response) => {
        if (response.success) {
          switch (response.authenticationStatus) {
            case 'RequiresTwoFactor':
              this.router.navigate(['/login2fa']);
              break;
            case 'RequiresTwoFactorSetup':
              this.router.navigate(['/setup2fa']);
              break;
            case 'Authenticated':
              this.router.navigate(['/dashboard']);
              break;
            default:
              this.loginError = 'Unknown authentication status.';
              break;
          }
        } else {
          this.loginError = response.message || 'Login failed. Please try again.';
        }
      },
      error: (err) => {
        this.loginError = err.error.message || 'Login failed. Please try again.';
        console.log(err);
      }
    });
  }
  

  goToRegister(): void {
    this.router.navigate(['/register']);
  }

  ngOnInit(): void {
    this.authService.isLoggedIn().subscribe((res) => {
      if (res.data.isAuthenticated) {
        this.router.navigate(['/dashboard']);
      } else if (res.data.requiresTwoFactor) {
        this.router.navigate(['/login2fa']);
      } else if (res.data.requiresTwoFactorSetup) {
        this.router.navigate(['/setup2fa']);
      } else {
        // Do nothing
      }
    })
  }

}
