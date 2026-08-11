import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface MitreTactic {
  id:         string;
  label:      string;
  count:      number;
  techniques: MitreTechnique[];
}

export interface MitreTechnique {
  id:      string;
  name:    string;
  count:   number;
  tactics: string[];
}

export interface MitreCoverage {
  total:      number;
  techniques: MitreTechnique[];
  tactics:    MitreTactic[];
  hours:      number;
}

@Injectable({ providedIn: 'root' })
export class MitreService {
  constructor(private api: ApiService) {}

  getCoverage(hours = 168, source = 'all'): Observable<MitreCoverage> {
    return this.api.get<MitreCoverage>('/mitre/coverage', { hours, source });
  }

  getTechniqueAlerts(techniqueId: string, hours = 168): Observable<any[]> {
    return this.api.get<any[]>(`/mitre/techniques/${techniqueId}/alerts`, { hours });
  }
}
