import { 
  AvailabilityResponse, 
  CdxRecord, 
  SavePageResponse, 
  MementoResponse,
  InternetArchiveApiConfig 
} from '@/types/internetArchive';

class InternetArchiveService {
  private config: InternetArchiveApiConfig = {
    availabilityEndpoint: 'https://archive.org/wayback/available',
    cdxEndpoint: 'http://web.archive.org/cdx/search/cdx',
    savePageEndpoint: 'https://web.archive.org/save',
    mementoEndpoint: 'http://web.archive.org/timemap/json'
  };

  /**
   * Availability API - Check if URL has archived snapshots
   */
  async checkAvailability(url: string, timestamp?: string): Promise<AvailabilityResponse> {
    try {
      const params = new URLSearchParams({ url });
      if (timestamp) {
        params.append('timestamp', timestamp);
      }

      const response = await fetch(`${this.config.availabilityEndpoint}?${params}`);
      if (!response.ok) {
        throw new Error(`Availability API error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error checking availability:', error);
      throw error;
    }
  }

  /**
   * CDX Server API - List snapshots with filtering
   */
  async searchCdx(options: {
    url: string;
    from?: string;
    to?: string;
    matchType?: 'exact' | 'prefix' | 'host' | 'domain';
    limit?: number;
    collapse?: string;
    filter?: string;
    output?: 'json' | 'text';
  }): Promise<CdxRecord[]> {
    try {
      const params = new URLSearchParams({
        url: options.url,
        output: options.output || 'json'
      });

      if (options.from) params.append('from', options.from);
      if (options.to) params.append('to', options.to);
      if (options.matchType) params.append('matchType', options.matchType);
      if (options.limit) params.append('limit', options.limit.toString());
      if (options.collapse) params.append('collapse', options.collapse);
      if (options.filter) params.append('filter', options.filter);

      const response = await fetch(`${this.config.cdxEndpoint}?${params}`);
      if (!response.ok) {
        throw new Error(`CDX API error: ${response.status}`);
      }

      const data = await response.json();
      
      // Convert array format to object format
      if (Array.isArray(data) && data.length > 0 && Array.isArray(data[0])) {
        return data.map((record: string[]) => ({
          urlkey: record[0],
          timestamp: record[1],
          original: record[2],
          mimetype: record[3],
          statuscode: record[4],
          digest: record[5],
          length: record[6]
        }));
      }

      return data;
    } catch (error) {
      console.error('Error searching CDX:', error);
      throw error;
    }
  }

  /**
   * Save Page Now API - Archive a page immediately
   */
  async savePage(url: string, options?: {
    capture_all?: boolean;
    capture_outlinks?: boolean;
    capture_screenshot?: boolean;
    delay_wb_availability?: boolean;
    force_get?: boolean;
    skip_first_archive?: boolean;
  }): Promise<SavePageResponse> {
    try {
      const params = new URLSearchParams({ url });
      
      if (options?.capture_all) params.append('capture_all', '1');
      if (options?.capture_outlinks) params.append('capture_outlinks', '1');
      if (options?.capture_screenshot) params.append('capture_screenshot', '1');
      if (options?.delay_wb_availability) params.append('delay_wb_availability', '1');
      if (options?.force_get) params.append('force_get', '1');
      if (options?.skip_first_archive) params.append('skip_first_archive', '1');

      const response = await fetch(`${this.config.savePageEndpoint}/${url}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`Save Page API error: ${response.status}`);
      }

      // Note: The actual response format may vary
      return {
        url,
        job_id: 'generated-' + Date.now(),
        status: 'pending'
      };
    } catch (error) {
      console.error('Error saving page:', error);
      throw error;
    }
  }

  /**
   * Memento API - Standards-based time travel
   */
  async getMementos(url: string): Promise<MementoResponse> {
    try {
      const response = await fetch(`${this.config.mementoEndpoint}/${url}`);
      if (!response.ok) {
        throw new Error(`Memento API error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting mementos:', error);
      throw error;
    }
  }

  /**
   * Get archived URL from timestamp
   */
  getArchivedUrl(url: string, timestamp: string): string {
    return `https://web.archive.org/web/${timestamp}/${url}`;
  }

  /**
   * Format timestamp for display
   */
  formatTimestamp(timestamp: string): string {
    if (timestamp.length === 14) {
      // Format: YYYYMMDDHHMMSS
      const year = timestamp.substring(0, 4);
      const month = timestamp.substring(4, 6);
      const day = timestamp.substring(6, 8);
      const hour = timestamp.substring(8, 10);
      const minute = timestamp.substring(10, 12);
      const second = timestamp.substring(12, 14);
      
      return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    }
    return timestamp;
  }

  /**
   * Parse timestamp to Date
   */
  parseTimestamp(timestamp: string): Date {
    if (timestamp.length === 14) {
      const year = parseInt(timestamp.substring(0, 4));
      const month = parseInt(timestamp.substring(4, 6)) - 1; // Month is 0-indexed
      const day = parseInt(timestamp.substring(6, 8));
      const hour = parseInt(timestamp.substring(8, 10));
      const minute = parseInt(timestamp.substring(10, 12));
      const second = parseInt(timestamp.substring(12, 14));
      
      return new Date(year, month, day, hour, minute, second);
    }
    return new Date(timestamp);
  }
}

export const internetArchiveService = new InternetArchiveService();