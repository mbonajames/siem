import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface Org {
  id:        string;
  name:      string;
  shortName: string;
  wazuhGroup?: string; // Wazuh agent group name — set when groups are configured
}

const ORGS: Org[] = [
  { id: 'all',          name: 'All Organizations', shortName: 'All Orgs'  },
  { id: 'hope-congo',   name: 'Hope Congo',         shortName: 'H. Congo', wazuhGroup: 'hope-congo'    },
  { id: 'urwego',       name: 'Urwego Finance',     shortName: 'Urwego',   wazuhGroup: 'urwego'         },
  { id: 'smep',         name: 'SMEP',               shortName: 'SMEP',     wazuhGroup: 'smep'           },
  { id: 'esperanza',    name: 'Esperanza',           shortName: 'Esperanza',wazuhGroup: 'esperanza'      },
  { id: 'csu',          name: 'CSU',                shortName: 'CSU',      wazuhGroup: 'csu'            },
  { id: 'turame',       name: 'Turame',              shortName: 'Turame',   wazuhGroup: 'turame'         },
  { id: 'ukraine',      name: 'Ukraine',             shortName: 'Ukraine',  wazuhGroup: 'ukraine'        },
];

const STORAGE_KEY = 'siem:selected_org';

@Injectable({ providedIn: 'root' })
export class OrgService {
  readonly orgs: Org[] = ORGS;

  private _selected$ = new BehaviorSubject<string>(
    localStorage.getItem(STORAGE_KEY) ?? 'all'
  );

  readonly org$ = this._selected$.asObservable();

  get orgId(): string  { return this._selected$.value; }
  get isAll():  boolean { return this._selected$.value === 'all'; }

  get current(): Org {
    return ORGS.find(o => o.id === this._selected$.value) ?? ORGS[0];
  }

  setOrg(id: string): void {
    localStorage.setItem(STORAGE_KEY, id);
    this._selected$.next(id);
  }

  /** Returns the Wazuh agent group for the selected org, or null when 'all'. */
  get wazuhGroup(): string | null {
    return this.isAll ? null : (this.current.wazuhGroup ?? null);
  }

  /** Query param object — add to any API call that needs org scoping. */
  get queryParam(): { org?: string } {
    return this.isAll ? {} : { org: this.orgId };
  }
}
