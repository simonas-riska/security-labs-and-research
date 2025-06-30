import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';

interface WeatherForecast {
  date: string;
  temperatureC: number;
  temperatureF: number;
  summary: string;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent implements OnInit {
  weatherData: WeatherForecast[] = [];
  errorMessage: string = '';

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit(): void {
      this.authService.isLoggedIn().subscribe((res) => {
        if (res.data.isAuthenticated) {
          // Do nothing
        } else if (res.data.requiresTwoFactor) {
          this.router.navigate(['/login2fa']);
        } else if (res.data.requiresTwoFactorSetup) {
          this.router.navigate(['/setup2fa']);
        } else {
          this.router.navigate(['/login']);
        }
      })

    this.authService.getWeatherForecast().subscribe(
      (data) => {
        this.weatherData = data;
      },
      (error) => {
        this.errorMessage = 'Failed to load weather data.';
      }
    );
  }

  logout(): void {
    this.authService.logout().subscribe(
      (response) => {
        if (response.success)
          this.router.navigate(['/login']);
      },
      (error) => {
        this.errorMessage = 'Logout failed. Please try again.';
      }
    );
  }
}
