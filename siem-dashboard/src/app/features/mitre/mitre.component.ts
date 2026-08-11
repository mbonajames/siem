import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MitreService, MitreCoverage, MitreTactic, MitreTechnique } from '../../core/services/mitre.service';

@Component({
  selector: 'app-mitre',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule, MatButtonModule, MatTooltipModule, MatProgressSpinnerModule],
  templateUrl: './mitre.component.html',
  styleUrl: './mitre.component.scss',
})
export class MitreComponent implements OnInit {
  loading  = true;
  coverage: MitreCoverage | null = null;
  selectedHours = 168;
  selectedSource = 'all';

  timeRanges = [
    { label: '24h',  value: 24   },
    { label: '7d',   value: 168  },
    { label: '30d',  value: 720  },
    { label: '90d',  value: 2160 },
  ];

  sources = [
    { label: 'All Sources', value: 'all'      },
    { label: 'Wazuh',       value: 'wazuh'    },
    { label: 'Defender',    value: 'ms-defender' },
    { label: 'Darktrace',   value: 'darktrace' },
  ];

  selectedTactic: MitreTactic | null = null;

  constructor(private mitre: MitreService, private router: Router) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.mitre.getCoverage(this.selectedHours, this.selectedSource).subscribe({
      next:  c => { this.coverage = c; this.loading = false; },
      error: () => { this.loading = false; },
    });
  }

  maxCount(): number {
    if (!this.coverage) return 1;
    return Math.max(...this.coverage.tactics.map(t => t.count), 1);
  }

  heatLevel(count: number): number {
    const max = this.maxCount();
    if (max === 0 || count === 0) return 0;
    return Math.ceil((count / max) * 5);
  }

  selectTactic(tactic: MitreTactic): void {
    this.selectedTactic = this.selectedTactic?.id === tactic.id ? null : tactic;
  }

  goToAlerts(tech: MitreTechnique): void {
    this.router.navigate(['/alerts'], {
      queryParams: { q: tech.id, hours: this.selectedHours }
    });
  }

  get displayedTechniques(): MitreTechnique[] {
    if (!this.coverage) return [];
    if (this.selectedTactic) return this.selectedTactic.techniques;
    return this.coverage.techniques.slice(0, 20);
  }
}
