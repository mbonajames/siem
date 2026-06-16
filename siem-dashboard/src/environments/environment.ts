export const environment = {
  production: false,
  apiBaseUrl: '/api',
  msal: {
    clientId: 'd989e502-4133-484d-8de2-c36d9a70c8df',
    tenantId: '27439031-8cd6-49af-b8b4-6f97e6cdf6d3',
    redirectUri: window.location.origin,
    // Full scope string from App Registration → Expose an API
    apiScope: 'api://d989e502-4133-484d-8de2-c36d9a70c8df/siem.access',
  }
};
