/**
 * GVM XML/JSON Transformers
 * Converts GVM XML responses to JSON structures for UI rendering
 */

import { GvmTarget, GvmTask } from '@/types/security';

/**
 * Parse XML string to Document
 */
const parseXML = (xmlString: string): Document => {
  const parser = new DOMParser();
  return parser.parseFromString(xmlString, 'text/xml');
};

/**
 * Get text content from XML node
 */
const getTextContent = (node: Element, tagName: string, defaultValue = ''): string => {
  const element = node.getElementsByTagName(tagName)[0];
  return element?.textContent || defaultValue;
};

/**
 * Transform GVM targets XML to JSON
 */
export const transformTargets = (xml: string): GvmTarget[] => {
  try {
    const doc = parseXML(xml);
    const targets = doc.getElementsByTagName('target');
    
    return Array.from(targets).map(target => ({
      id: target.getAttribute('id') || '',
      name: getTextContent(target, 'name'),
      hosts: getTextContent(target, 'hosts').split(',').map(h => h.trim()).filter(Boolean),
      comment: getTextContent(target, 'comment'),
      port_list_id: target.getElementsByTagName('port_list')[0]?.getAttribute('id') || undefined,
    }));
  } catch (error) {
    console.error('Failed to transform targets XML:', error);
    return [];
  }
};

/**
 * Transform GVM tasks XML to JSON
 */
export const transformTasks = (xml: string): GvmTask[] => {
  try {
    const doc = parseXML(xml);
    const tasks = doc.getElementsByTagName('task');
    
    return Array.from(tasks).map(task => {
      const status = getTextContent(task, 'status', 'New') as GvmTask['status'];
      const progressText = getTextContent(task, 'progress', '0');
      const progress = parseInt(progressText, 10) || 0;
      
      const targetElement = task.getElementsByTagName('target')[0];
      const configElement = task.getElementsByTagName('config')[0];
      const lastReportElement = task.getElementsByTagName('last_report')[0];
      
      return {
        id: task.getAttribute('id') || '',
        name: getTextContent(task, 'name'),
        status,
        progress,
        target: {
          id: targetElement?.getAttribute('id') || '',
          name: getTextContent(targetElement as Element, 'name'),
        },
        config: {
          id: configElement?.getAttribute('id') || '',
          name: getTextContent(configElement as Element, 'name'),
        },
        last_report: lastReportElement ? {
          id: lastReportElement.getAttribute('id') || '',
          timestamp: getTextContent(lastReportElement as Element, 'timestamp'),
        } : undefined,
        comment: getTextContent(task, 'comment'),
      };
    });
  } catch (error) {
    console.error('Failed to transform tasks XML:', error);
    return [];
  }
};

/**
 * Transform GVM report XML to simplified structure
 */
export const transformReport = (xml: string) => {
  try {
    const doc = parseXML(xml);
    const report = doc.getElementsByTagName('report')[0];
    
    if (!report) {
      throw new Error('No report element found in XML');
    }
    
    const results = Array.from(report.getElementsByTagName('result')).map(result => ({
      id: result.getAttribute('id') || '',
      name: getTextContent(result, 'name'),
      severity: parseFloat(getTextContent(result, 'severity', '0')),
      description: getTextContent(result, 'description'),
      host: getTextContent(result, 'host'),
      port: getTextContent(result, 'port'),
      nvt: {
        oid: getTextContent(result, 'nvt/oid'),
        name: getTextContent(result, 'nvt/name'),
        family: getTextContent(result, 'nvt/family'),
        cvss_base: getTextContent(result, 'nvt/cvss_base'),
      },
    }));
    
    return {
      id: report.getAttribute('id') || '',
      timestamp: getTextContent(report, 'timestamp'),
      scan_start: getTextContent(report, 'scan_start'),
      scan_end: getTextContent(report, 'scan_end'),
      results,
      resultCount: {
        total: results.length,
        high: results.filter(r => r.severity >= 7.0).length,
        medium: results.filter(r => r.severity >= 4.0 && r.severity < 7.0).length,
        low: results.filter(r => r.severity > 0 && r.severity < 4.0).length,
        info: results.filter(r => r.severity === 0).length,
      },
    };
  } catch (error) {
    console.error('Failed to transform report XML:', error);
    return null;
  }
};