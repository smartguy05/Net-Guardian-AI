import { useState, useRef, useEffect } from 'react';
import {
  MessageSquare,
  Send,
  Bot,
  User,
  Loader2,
  AlertCircle,
  Sparkles,
  Zap,
  Brain,
} from 'lucide-react';
import { useLLMStatus, useNetworkQuery } from '../api/hooks';
import type { ChatMessage, LLMStatus } from '../types';
import clsx from 'clsx';

const getModelOptions = (llmStatus: LLMStatus | undefined) => [
  { value: 'fast' as const, label: `Fast (${llmStatus?.model_fast || 'loading...'})`, icon: Zap, description: 'Quick responses' },
  { value: 'default' as const, label: `Balanced (${llmStatus?.model_default || 'loading...'})`, icon: Sparkles, description: 'Best quality' },
  { value: 'deep' as const, label: `Deep (${llmStatus?.model_deep || 'loading...'})`, icon: Brain, description: 'Detailed analysis' },
];

const suggestedQueries = [
  'What devices are most active right now?',
  'Are there any security concerns I should know about?',
  'Show me the top blocked domains today',
  'Which devices have anomalies?',
  'Summarize my network activity for the last 24 hours',
];

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [selectedModel, setSelectedModel] = useState<'fast' | 'default' | 'deep'>('default');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { data: llmStatus, isLoading: statusLoading } = useLLMStatus();
  const queryMutation = useNetworkQuery();

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || queryMutation.isPending) return;

    const userMessage: ChatMessage = { role: 'user', content: input.trim() };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');

    try {
      const response = await queryMutation.mutateAsync({
        query: input.trim(),
        model: selectedModel,
      });

      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: response.response,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: ChatMessage = {
        role: 'assistant',
        content: 'Sorry, I encountered an error processing your request. Please try again.',
      };
      setMessages((prev) => [...prev, errorMessage]);
    }
  };

  const handleSuggestedQuery = (query: string) => {
    setInput(query);
  };

  if (statusLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-primary-600" />
      </div>
    );
  }

  if (!llmStatus?.configured) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Assistant</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Chat with Claude about your network security
          </p>
        </div>

        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-6">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-6 w-6 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-medium text-amber-800 dark:text-amber-300">LLM Service Not Configured</h3>
              <p className="mt-1 text-sm text-amber-700 dark:text-amber-400">
                The AI assistant requires an Anthropic API key to function. Please add your
                API key to the environment configuration:
              </p>
              <pre className="mt-3 p-3 bg-amber-100 dark:bg-amber-900/30 rounded text-sm text-amber-900 dark:text-amber-200 overflow-x-auto">
                ANTHROPIC_API_KEY=sk-ant-your-api-key
              </pre>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Assistant</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Ask questions about your network security
          </p>
        </div>

        {/* Model selector */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">Model:</span>
          <div className="flex rounded-lg border border-gray-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 p-1">
            {getModelOptions(llmStatus).map((option) => (
              <button
                key={option.value}
                onClick={() => setSelectedModel(option.value)}
                className={clsx(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                  selectedModel === option.value
                    ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                    : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700'
                )}
                title={option.description}
              >
                <option.icon className="h-4 w-4" />
                <span className="hidden sm:inline">{option.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chat container */}
      <div className="flex-1 bg-white dark:bg-zinc-800 rounded-lg border border-gray-200 dark:border-zinc-700 flex flex-col overflow-hidden">
        {/* Messages area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center">
              <div className="w-16 h-16 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center mb-4">
                <MessageSquare className="h-8 w-8 text-primary-600 dark:text-primary-400" />
              </div>
              <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                How can I help you today?
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 max-w-md mb-6">
                Ask me anything about your network security, devices, alerts, or anomalies.
                I have access to your current network state and can help you understand what's
                happening.
              </p>

              {/* Suggested queries */}
              <div className="space-y-2 w-full max-w-lg">
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Try asking
                </p>
                <div className="flex flex-wrap justify-center gap-2">
                  {suggestedQueries.map((query, index) => (
                    <button
                      key={index}
                      onClick={() => handleSuggestedQuery(query)}
                      className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-zinc-700 hover:bg-gray-200 dark:hover:bg-zinc-600 rounded-full text-gray-700 dark:text-gray-200 transition-colors"
                    >
                      {query}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            messages.map((message, index) => (
              <div
                key={index}
                className={clsx(
                  'flex gap-3',
                  message.role === 'user' ? 'justify-end' : 'justify-start'
                )}
              >
                {message.role === 'assistant' && (
                  <div className="flex-shrink-0 w-8 h-8 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center">
                    <Bot className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                  </div>
                )}
                <div
                  className={clsx(
                    'max-w-[70%] rounded-lg px-4 py-2',
                    message.role === 'user'
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 dark:bg-zinc-700 text-gray-900 dark:text-gray-100'
                  )}
                >
                  <p className="whitespace-pre-wrap">{message.content}</p>
                </div>
                {message.role === 'user' && (
                  <div className="flex-shrink-0 w-8 h-8 bg-gray-200 dark:bg-zinc-600 rounded-full flex items-center justify-center">
                    <User className="h-5 w-5 text-gray-600 dark:text-gray-300" />
                  </div>
                )}
              </div>
            ))
          )}

          {queryMutation.isPending && (
            <div className="flex gap-3 justify-start">
              <div className="flex-shrink-0 w-8 h-8 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center">
                <Bot className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div className="bg-gray-100 dark:bg-zinc-700 rounded-lg px-4 py-2 flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-gray-500 dark:text-gray-400" />
                <span className="text-gray-500 dark:text-gray-400">Thinking...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input area */}
        <div className="border-t border-gray-200 dark:border-zinc-700 p-4">
          <form onSubmit={handleSubmit} className="flex gap-3">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about your network security..."
              className="flex-1 rounded-lg border border-gray-300 dark:border-zinc-600 bg-white dark:bg-zinc-900 text-gray-900 dark:text-white px-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent placeholder-gray-400 dark:placeholder-gray-500"
              disabled={queryMutation.isPending}
            />
            <button
              type="submit"
              disabled={!input.trim() || queryMutation.isPending}
              className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
            >
              {queryMutation.isPending ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Send className="h-5 w-5" />
              )}
              <span className="hidden sm:inline">Send</span>
            </button>
          </form>

          {queryMutation.isError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">
              Failed to get response. Please try again.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
