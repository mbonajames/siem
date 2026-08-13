import { Component, ViewChild } from '@angular/core';
import { Router, RouterOutlet } from '@angular/router';
import { MatSidenavModule } from '@angular/material/sidenav';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { HeaderComponent } from '../header/header.component';

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [RouterOutlet, MatSidenavModule, SidebarComponent, HeaderComponent],
  templateUrl: './shell.component.html',
  styleUrl: './shell.component.scss',
})
export class ShellComponent {
  @ViewChild(HeaderComponent) private header!: HeaderComponent;

  sidenavOpen = true;

  constructor(private router: Router) {}

  toggleSidenav(): void {
    this.sidenavOpen = !this.sidenavOpen;
  }

  // Fires on every component activation — both fresh mounts and KEEP_ALIVE re-attachments.
  onActivate(component: any): void {
    // Sync the header title immediately (bypasses NavigationEnd timing issues).
    this.header?.syncTitle(this.router.url);
    // If the component was reattached with empty/errored state, let it reload.
    component?.onReuse?.();
  }
}
