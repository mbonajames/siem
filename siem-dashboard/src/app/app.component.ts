import { Component, OnInit, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { AuthService } from './core/services/auth.service';
import { GatewayService } from './core/services/gateway.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class AppComponent implements OnInit {
  private readonly auth    = inject(AuthService);
  private readonly gateway = inject(GatewayService);

  ngOnInit(): void {
    if (this.auth.account && !this.auth.loginAlreadyRecorded) {
      this.auth.markLoginRecorded();
      this.gateway.recordLogin(this.auth.user?.email, this.auth.user?.name).subscribe();
    }
  }
}
