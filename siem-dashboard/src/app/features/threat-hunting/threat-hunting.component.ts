import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { SavedSearchesService, SavedSearch, SavedSearchList } from '../../core/services/saved-searches.service';

@Component({
  selector: 'app-threat-hunting',
  standalone: true,
  imports: [
    CommonModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatProgressSpinnerModule, MatDialogModule, MatSnackBarModule,
  ],
  templateUrl: './threat-hunting.component.html',
  styleUrl: './threat-hunting.component.scss',
})
export class ThreatHuntingComponent implements OnInit {
  loading = true;
  searches: SavedSearchList = { builtin: [], saved: [] };

  constructor(
    private svc: SavedSearchesService,
    private router: Router,
    private snackBar: MatSnackBar,
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.svc.list().subscribe({
      next:  s => { this.searches = s; this.loading = false; },
      error: () => { this.loading = false; },
    });
  }

  run(s: SavedSearch): void {
    const params: Record<string, any> = {};
    if (s.filters['severity'])    params['severity']  = s.filters['severity'];
    if (s.filters['source'])      params['source']    = s.filters['source'];
    if (s.filters['q'])           params['q']         = s.filters['q'];
    if (s.filters['hours'])       params['hours']     = s.filters['hours'];
    if (s.filters['eventType'])   params['eventType'] = s.filters['eventType'];
    this.router.navigate(['/alerts'], { queryParams: params });
  }

  delete(s: SavedSearch): void {
    this.svc.delete(s.id || s._id!).subscribe({
      next:  () => { this.snackBar.open('Search deleted', '', { duration: 2500 }); this.load(); },
      error: () => { this.snackBar.open('Delete failed', '', { duration: 2500 }); },
    });
  }

  get allSearches(): SavedSearch[] {
    return [...this.searches.builtin, ...this.searches.saved];
  }

  categoryGroups(): string[] {
    const cats = new Set(this.allSearches.map(s => s.category));
    return Array.from(cats);
  }

  byCategory(cat: string): SavedSearch[] {
    return this.allSearches.filter(s => s.category === cat);
  }
}
