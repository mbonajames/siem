import { Component } from '@angular/core';

@Component({
  selector: 'app-auth-redirect',
  standalone: true,
  imports: [],
  template: `
    <div class="redirect-container">
      <span>Completing sign-in&hellip;</span>
    </div>
  `,
  styles: [`
    .redirect-container {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      background: #0d1117;
      color: #8b949e;
      font-size: 14px;
    }
  `],
})
export class AuthRedirectComponent {}
