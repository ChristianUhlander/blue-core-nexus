export interface AvailabilityResponse {
  url: string;
  archived_snapshots: {
    closest?: {
      available: boolean;
      url: string;
      timestamp: string;
      status: string;
    };
  };
}

export interface CdxRecord {
  urlkey: string;
  timestamp: string;
  original: string;
  mimetype: string;
  statuscode: string;
  digest: string;
  length: string;
}

export interface SavePageResponse {
  url: string;
  job_id: string;
  status: 'pending' | 'success' | 'error';
  message?: string;
}

export interface MementoResponse {
  original_uri: string;
  timegate_uri: string;
  first_memento_datetime: string;
  last_memento_datetime: string;
  mementos: Array<{
    datetime: string;
    uri: string;
    rel: string;
  }>;
}

export interface InternetArchiveApiConfig {
  availabilityEndpoint: string;
  cdxEndpoint: string;
  savePageEndpoint: string;
  mementoEndpoint: string;
}