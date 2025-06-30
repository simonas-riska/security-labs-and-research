import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent implements OnInit{
  
  registerForm: FormGroup;
  registrationSuccess: boolean | null = null;
  registrationMessage: string = '';
  
  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
    this.registerForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', [Validators.required, Validators.minLength(6)]],
      email: ['', [Validators.required, Validators.email]],
      name: ['', Validators.required],
    });
  }

  
  onSubmit() {
    if (this.registerForm.valid) {
      this.authService.register(this.registerForm.value).subscribe({
        next: (response) => {
          this.registrationSuccess = response.success;
          this.registrationMessage = response.message;
        },
        error: (err) => {
          this.registrationSuccess = false;
          this.registrationMessage = err.response.error.messages.join('\n');
          console.error('Registration error:', err);
        },
      });
    }
  }

  ngOnInit(): void {
    this.authService.isLoggedIn().subscribe((res) => {
      if (res.data.isAuthenticated) {
        this.router.navigate(['/dashboard']);
      } else if (res.data.requiresTwoFactor) {
        this.router.navigate(['/login2fa']);
      } else if (res.data.requiresTwoFactorSetup) {
        this.router.navigate(['/setup2fa']);
      }
    })
  }

  logout(): void {

          this.router.navigate(['/login']);
  }
}
