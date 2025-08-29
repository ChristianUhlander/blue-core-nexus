/**
 * OpenAI Service for AI-powered report generation
 * Handles communication with OpenAI API for intelligent content generation
 */

export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface OpenAIRequest {
  model: string;
  messages: OpenAIMessage[];
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
}

export interface OpenAIResponse {
  choices: Array<{
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export class OpenAIService {
  private apiKey: string;
  private baseUrl: string = 'https://api.openai.com/v1';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async generateChatCompletion(request: OpenAIRequest): Promise<OpenAIResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: request.model,
          messages: request.messages,
          temperature: request.temperature || 0.7,
          max_tokens: request.max_tokens || 2000,
          top_p: request.top_p || 1,
          frequency_penalty: request.frequency_penalty || 0,
          presence_penalty: request.presence_penalty || 0,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`OpenAI API error: ${response.status} - ${errorData.error?.message || response.statusText}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('OpenAI API call failed:', error);
      throw error;
    }
  }

  async generateSecurityReport(
    reportData: any,
    audienceType: string,
    templateName: string,
    customInstructions?: string
  ): Promise<string> {
    const systemPrompt = `You are an expert cybersecurity report writer. You specialize in creating comprehensive, actionable security reports tailored to specific audiences.

Your task is to generate a security report for ${audienceType} using the template "${templateName}".

Report Guidelines:
- Use clear, professional language appropriate for the target audience
- Include specific technical details when addressing technical audiences
- Focus on business impact and ROI for executive audiences
- Provide actionable recommendations with clear priorities
- Include relevant code examples and implementation guidance where appropriate
- Reference current security standards and best practices
- Format the report with proper sections and subsections

${customInstructions ? `Additional Instructions: ${customInstructions}` : ''}`;

    const userPrompt = `Generate a comprehensive security report based on the following data:

Security Data:
${JSON.stringify(reportData, null, 2)}

Please create a well-structured report that includes:
1. Executive Summary
2. Key Findings
3. Risk Assessment
4. Detailed Analysis
5. Recommendations
6. Next Steps
7. Appendices (if applicable)

Make sure the report is tailored for the ${audienceType} audience and follows the ${templateName} template structure.`;

    const request: OpenAIRequest = {
      model: 'gpt-4',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.3,
      max_tokens: 4000
    };

    const response = await this.generateChatCompletion(request);
    return response.choices[0]?.message?.content || 'Failed to generate report content';
  }

  async enhanceWithResearch(content: string, researchData: string): Promise<string> {
    const systemPrompt = `You are a security research analyst. Your task is to enhance existing security report content with the latest research findings and best practices.

Guidelines:
- Integrate research findings seamlessly into the existing content
- Add relevant code examples and implementation details
- Update recommendations based on the latest security research
- Maintain the original report structure and tone
- Highlight new insights from the research data`;

    const userPrompt = `Enhance the following security report content with the provided research data:

Original Content:
${content}

Research Data:
${researchData}

Please enhance the content by integrating the research findings while maintaining the original structure and improving the overall quality and accuracy of the report.`;

    const request: OpenAIRequest = {
      model: 'gpt-4',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.2,
      max_tokens: 4000
    };

    const response = await this.generateChatCompletion(request);
    return response.choices[0]?.message?.content || content; // Return original if enhancement fails
  }

  async generateExecutiveSummary(detailedReport: string): Promise<string> {
    const systemPrompt = `You are an executive communication specialist. Create concise, high-level executive summaries that focus on business impact, risk levels, and strategic recommendations.

Guidelines:
- Keep it concise (2-3 paragraphs maximum)
- Focus on business impact and ROI
- Highlight critical risks and priorities
- Provide clear action items for leadership
- Use business-friendly language, avoid technical jargon`;

    const userPrompt = `Create an executive summary for the following detailed security report:

${detailedReport}

The summary should be suitable for C-level executives and board members, focusing on business implications and strategic decisions.`;

    const request: OpenAIRequest = {
      model: 'gpt-4',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.2,
      max_tokens: 800
    };

    const response = await this.generateChatCompletion(request);
    return response.choices[0]?.message?.content || 'Unable to generate executive summary';
  }
}

// Utility function to create OpenAI service instance
export const createOpenAIService = (apiKey: string): OpenAIService => {
  return new OpenAIService(apiKey);
};