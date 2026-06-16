import { Component, OnInit, AfterViewInit, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { MatPaginatorModule, MatPaginator } from '@angular/material/paginator';
import { MatSortModule, MatSort } from '@angular/material/sort';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTabsModule } from '@angular/material/tabs';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { WazuhService } from '../../core/services/wazuh.service';
import { forkJoin } from 'rxjs';

@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatTableModule, MatPaginatorModule, MatSortModule,
    MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatIconModule,
    MatCardModule, MatProgressBarModule, MatTabsModule, MatChipsModule, MatTooltipModule
  ],
  templateUrl: './rules.component.html',
  styleUrl: './rules.component.scss'
})
export class RulesComponent implements OnInit, AfterViewInit {
  @ViewChild('rulesPaginator')   rulesPaginator!: MatPaginator;
  @ViewChild('decodersPaginator') decodersPaginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  loading = false;
  rulesColumns    = ['id', 'level', 'description', 'groups', 'mitre', 'filename'];
  decodersColumns = ['name', 'program_name', 'parent', 'filename'];

  rulesDataSource    = new MatTableDataSource<any>([]);
  decodersDataSource = new MatTableDataSource<any>([]);

  rulesSearch    = '';
  decodersSearch = '';
  selectedLevel  = '';

  levels = [
    { value: '',   label: 'All Levels' },
    { value: '13', label: '13+ Critical' },
    { value: '10', label: '10+ High' },
    { value: '7',  label: '7+ Medium' },
    { value: '4',  label: '4+ Low' }
  ];

  constructor(private wazuh: WazuhService) {}

  ngOnInit(): void { this.loadRules(); }

  ngAfterViewInit(): void {
    this.rulesDataSource.paginator    = this.rulesPaginator;
    this.decodersDataSource.paginator = this.decodersPaginator;
    this.rulesDataSource.sort         = this.sort;
  }

  loadRules(): void {
    this.loading = true;
    forkJoin({
      rules:    this.wazuh.getRules({ limit: 500 }),
      decoders: this.wazuh.getDecoders({ limit: 500 })
    }).subscribe({
      next: (data) => {
        this.rulesDataSource.data    = data.rules?.data?.affected_items    ?? [];
        this.decodersDataSource.data = data.decoders?.data?.affected_items ?? [];
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });
  }

  filterRules(): void {
    this.rulesDataSource.filterPredicate = (row: any, filter: string) => {
      const { search, level } = JSON.parse(filter);
      const matchSearch = !search ||
        row.description?.toLowerCase().includes(search.toLowerCase()) ||
        String(row.id).includes(search);
      const matchLevel  = !level || row.level >= parseInt(level);
      return matchSearch && matchLevel;
    };
    this.rulesDataSource.filter = JSON.stringify({ search: this.rulesSearch, level: this.selectedLevel });
  }

  filterDecoders(): void {
    const f = this.decodersSearch.trim().toLowerCase();
    this.decodersDataSource.filterPredicate = (row: any, filter: string) =>
      row.name?.toLowerCase().includes(filter) || row.program_name?.toLowerCase().includes(filter);
    this.decodersDataSource.filter = f;
  }

  getMitreIds(row: any): string[] {
    return row.mitre?.id ?? [];
  }

  getLevelClass(level: number): string {
    if (level >= 15) return 'critical';
    if (level >= 12) return 'high';
    if (level >= 7)  return 'medium';
    return 'low';
  }
}
