import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface SavedSearch {
  id:          string;
  name:        string;
  description: string;
  category:    string;
  icon:        string;
  color:       string;
  filters:     Record<string, any>;
  is_builtin:  boolean;
  created_by?: string;
  created_at?: string;
  _id?:        string;
}

export interface SavedSearchList {
  builtin: SavedSearch[];
  saved:   SavedSearch[];
}

export interface SaveSearchPayload {
  name:        string;
  description: string;
  category:    string;
  icon:        string;
  color:       string;
  filters:     Record<string, any>;
}

@Injectable({ providedIn: 'root' })
export class SavedSearchesService {
  constructor(private api: ApiService) {}

  list(): Observable<SavedSearchList> {
    return this.api.get<SavedSearchList>('/saved-searches');
  }

  create(payload: SaveSearchPayload): Observable<SavedSearch> {
    return this.api.post<SavedSearch>('/saved-searches', payload);
  }

  delete(id: string): Observable<void> {
    return this.api.delete<void>(`/saved-searches/${id}`);
  }
}
