import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ConnectorsService, Connector } from '../../core/services/connectors.service';

interface ConnectorVM extends Connector {
  testing: boolean;
  testDetail: string;
}

const CATEGORY_ORDER = ['SIEM', 'Endpoint', 'Network', 'Identity', 'Scanner', 'Threat Intel', 'Ticketing', 'Future'];

@Component({
  selector: 'app-connectors',
  standalone: true,
  imports: [CommonModule, MatIconModule, MatButtonModule, MatTooltipModule, MatProgressSpinnerModule],
  templateUrl: './connectors.component.html',
  styleUrl:    './connectors.component.scss',
})
export class ConnectorsComponent implements OnInit {
  loading   = true;
  connectors: ConnectorVM[] = [];
  categories: string[] = [];

  constructor(private svc: ConnectorsService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
  }

  onReuse(): void {
    if (!this.connectors.length || this.loading) {
      this.load();
    }
  }

  load(): void {
    this.loading = true;
    this.svc.list().subscribe({
      next: list => {
        this.connectors = list.map(c => ({ ...c, testing: false, testDetail: '' }));
        this.categories = CATEGORY_ORDER.filter(cat =>
          this.connectors.some(c => c.category === cat)
        );
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); },
    });
  }

  byCategory(cat: string): ConnectorVM[] {
    return this.connectors.filter(c => c.category === cat);
  }

  get totalConfigured(): number { return this.connectors.filter(c => c.configured).length; }
  get totalConnected():  number { return this.connectors.filter(c => c.status === 'connected').length; }

  test(c: ConnectorVM): void {
    if (c.testing) return;
    c.testing    = true;
    c.testDetail = '';
    this.svc.test(c.id).subscribe({
      next: result => {
        c.status     = result.status as any;
        c.testDetail = result.detail;
        c.testing    = false;
        c.last_checked = result.checked;
        this.cdr.detectChanges();
      },
      error: () => {
        c.status     = 'disconnected';
        c.testDetail = 'Connection failed';
        c.testing    = false;
        this.cdr.detectChanges();
      },
    });
  }

  statusLabel(c: ConnectorVM): string {
    if (!c.configured)            return 'Not Configured';
    if (c.status === 'connected') return 'Connected';
    if (c.status === 'disconnected') return 'Disconnected';
    return 'Unknown';
  }

  statusClass(c: ConnectorVM): string {
    if (!c.configured)            return 'status-unconfigured';
    if (c.status === 'connected') return 'status-connected';
    if (c.status === 'disconnected') return 'status-disconnected';
    return 'status-unknown';
  }

  trackById(_: number, c: ConnectorVM): string { return c.id; }
}
