import { Routes } from '@angular/router';
import { RegisterComponent } from './components/register/register.component';
import { LoginComponent } from './components/login/login.component';
import { Setup2faComponent } from './components/setup2fa/setup2fa.component';
import { Login2faComponent } from './components/login2fa/login2fa.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';

  export const routes: Routes = [
    { path: '', redirectTo: '/login', pathMatch: 'full' },
  
    { path: 'login', component: LoginComponent},

    { path: 'register', component: RegisterComponent},
  
    { path: 'setup2fa', component: Setup2faComponent},
  
    { path: 'login2fa', component: Login2faComponent},
  
    { path: 'dashboard', component: DashboardComponent},
  
    { path: '**', redirectTo: '/login' },
  ];