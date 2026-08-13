import { Component, OnInit, inject } from '@angular/core';
import { Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [MatButtonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
})
export class LoginComponent implements OnInit {
  private readonly auth   = inject(AuthService);
  private readonly router = inject(Router);

  ngOnInit(): void {
    if (this.auth.account) {
      this.router.navigate(['/dashboard'], { replaceUrl: true });
    }
  }

  signIn(): void {
    this.auth.login();
  }
}
