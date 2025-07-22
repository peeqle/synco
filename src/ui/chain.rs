use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

/// Базовый трейт для модулей/интерцепторов
#[async_trait]
pub trait Module: Send + Sync {
    /// Уникальный идентификатор модуля
    fn id(&self) -> &'static str;
    
    /// Приоритет выполнения (меньше = раньше выполняется)
    fn priority(&self) -> i32 { 100 }
    
    /// Инициализация модуля
    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError>;
    
    /// Завершение работы модуля
    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError>;
    
    /// Обработка события
    async fn handle_event(&mut self, event: &ModuleEvent, context: &mut ModuleContext) -> Result<EventResult, ModuleError>;
    
    /// Проверка, может ли модуль обработать данное событие
    fn can_handle(&self, event: &ModuleEvent) -> bool;
    
    /// Получение метаданных модуля
    fn metadata(&self) -> ModuleMetadata;
}

/// Расширенный трейт для модулей с UI компонентами
#[async_trait]
pub trait UIModule: Module {
    /// Отрисовка UI компонента модуля
    fn draw(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, context: &ModuleContext);
    
    /// Обработка UI событий
    async fn handle_ui_event(&mut self, event: crossterm::event::KeyEvent, context: &mut ModuleContext) -> Result<(), ModuleError>;
    
    /// Получение имени вкладки для UI
    fn tab_name(&self) -> &'static str;
    
    /// Активен ли модуль в данный момент в UI
    fn is_active(&self) -> bool { true }
}

/// Контекст выполнения модуля
#[derive(Clone)]
pub struct ModuleContext {
    pub shared_state: Arc<Mutex<HashMap<String, Box<dyn Any + Send + Sync>>>>,
    pub event_bus: Arc<EventBus>,
    pub config: Arc<ModuleConfig>,
}

/// Шина событий для коммуникации между модулями
#[derive(Default)]
pub struct EventBus {
    listeners: Arc<Mutex<HashMap<String, Vec<Box<dyn Fn(&ModuleEvent) + Send + Sync>>>>>,
}

/// Конфигурация модулей
#[derive(Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled_modules: Vec<String>,
    pub module_settings: HashMap<String, serde_json::Value>,
}

/// События в системе
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleEvent {
    /// Системные события
    System(SystemEvent),
    /// События сети
    Network(NetworkEvent),
    /// События файловой системы
    FileSystem(FileSystemEvent),
    /// UI события
    UI(UIEvent),
    /// Пользовательские события
    Custom { event_type: String, data: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEvent {
    Startup,
    Shutdown,
    ModuleLoaded(String),
    ModuleUnloaded(String),
    ConfigChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    DeviceDiscovered(String),
    DeviceConnected(String),
    DeviceDisconnected(String),
    DataReceived { from: String, data: Vec<u8> },
    ConnectionError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileSystemEvent {
    FileCreated(String),
    FileModified(String),
    FileDeleted(String),
    SyncStarted(String),
    SyncCompleted { path: String, success: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UIEvent {
    TabChanged(usize),
    KeyPressed(String),
    Refresh,
}

/// Результат обработки события
#[derive(Debug, Clone)]
pub enum EventResult {
    /// Событие обработано, продолжить цепочку
    Continue,
    /// Событие обработано, остановить цепочку
    Stop,
    /// Событие обработано с ошибкой
    Error(String),
    /// Породить новые события
    Emit(Vec<ModuleEvent>),
}

/// Ошибки модульной системы
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Event handling failed: {0}")]
    EventHandlingFailed(String),
    #[error("Module not found: {0}")]
    ModuleNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Метаданные модуля
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub dependencies: Vec<String>,
    pub tags: Vec<String>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub async fn emit(&self, event: ModuleEvent) {
        let listeners = self.listeners.lock().await;
        let event_type = match &event {
            ModuleEvent::System(_) => "system",
            ModuleEvent::Network(_) => "network",
            ModuleEvent::FileSystem(_) => "filesystem",
            ModuleEvent::UI(_) => "ui",
            ModuleEvent::Custom { event_type, .. } => event_type,
        };
        
        if let Some(handlers) = listeners.get(event_type) {
            for handler in handlers.iter() {
                handler(&event);
            }
        }
    }
    
    pub async fn subscribe<F>(&self, event_type: &str, handler: F) 
    where 
        F: Fn(&ModuleEvent) + Send + Sync + 'static 
    {
        let mut listeners = self.listeners.lock().await;
        listeners.entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(Box::new(handler));
    }
}

impl ModuleContext {
    pub fn new(config: ModuleConfig) -> Self {
        Self {
            shared_state: Arc::new(Mutex::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new()),
            config: Arc::new(config),
        }
    }
    
    /// Получить значение из общего состояния
    pub async fn get_state<T: Clone + 'static>(&self, key: &str) -> Option<T> {
        let state = self.shared_state.lock().await;
        state.get(key)?.downcast_ref::<T>().cloned()
    }
    
    /// Установить значение в общее состояние
    pub async fn set_state<T: Send + Sync + 'static>(&self, key: &str, value: T) {
        let mut state = self.shared_state.lock().await;
        state.insert(key.to_string(), Box::new(value));
    }
    
    /// Отправить событие
    pub async fn emit_event(&self, event: ModuleEvent) {
        self.event_bus.emit(event).await;
    }
}

/// Менеджер модулей
pub struct ModuleManager {
    modules: Vec<Box<dyn Module>>,
    ui_modules: Vec<Box<dyn UIModule>>,
    context: ModuleContext,
}

impl ModuleManager {
    pub fn new(config: ModuleConfig) -> Self {
        Self {
            modules: Vec::new(),
            ui_modules: Vec::new(),
            context: ModuleContext::new(config),
        }
    }
    
    /// Зарегистрировать модуль
    pub fn register_module(&mut self, mut module: Box<dyn Module>) {
        self.modules.push(module);
        self.modules.sort_by_key(|m| m.priority());
    }
    
    /// Зарегистрировать UI модуль
    pub fn register_ui_module(&mut self, mut module: Box<dyn UIModule>) {
        self.ui_modules.push(module);
        self.ui_modules.sort_by_key(|m| m.priority());
    }
    
    /// Инициализировать все модули
    pub async fn init_all(&mut self) -> Result<(), ModuleError> {
        // Инициализируем обычные модули
        for module in &mut self.modules {
            module.init(&mut self.context).await?;
            self.context.emit_event(ModuleEvent::System(SystemEvent::ModuleLoaded(
                module.id().to_string()
            ))).await;
        }
        
        // Инициализируем UI модули
        for module in &mut self.ui_modules {
            module.init(&mut self.context).await?;
            self.context.emit_event(ModuleEvent::System(SystemEvent::ModuleLoaded(
                module.id().to_string()
            ))).await;
        }
        
        // Отправляем событие о запуске системы
        self.context.emit_event(ModuleEvent::System(SystemEvent::Startup)).await;
        
        Ok(())
    }

    pub async fn handle_event(&mut self, event: ModuleEvent) -> Result<(), ModuleError> {
        let mut events_to_process = vec![event];

        while let Some(current_event) = events_to_process.pop() {
            let mut new_events = Vec::new();

            for module in &mut self.modules {
                if module.can_handle(&current_event) {
                    match module.handle_event(&current_event, &mut self.context).await? {
                        EventResult::Stop => break,
                        EventResult::Error(err) => return Err(ModuleError::EventHandlingFailed(err)),
                        EventResult::Emit(events) => {
                            new_events.extend(events);
                        },
                        EventResult::Continue => continue,
                    }
                }
            }

            for module in &mut self.ui_modules {
                if module.can_handle(&current_event) {
                    match module.handle_event(&current_event, &mut self.context).await? {
                        EventResult::Stop => break,
                        EventResult::Error(err) => return Err(ModuleError::EventHandlingFailed(err)),
                        EventResult::Emit(events) => {
                            new_events.extend(events);
                        },
                        EventResult::Continue => continue,
                    }
                }
            }

            events_to_process.extend(new_events);
        }

        Ok(())
    }
    
    /// Получить UI модули
    pub fn get_ui_modules(&self) -> &Vec<Box<dyn UIModule>> {
        &self.ui_modules
    }
    
    /// Получить контекст
    pub fn get_context(&self) -> &ModuleContext {
        &self.context
    }
    
    /// Завершить работу всех модулей
    pub async fn shutdown(&mut self) -> Result<(), ModuleError> {
        self.context.emit_event(ModuleEvent::System(SystemEvent::Shutdown)).await;
        
        for module in &mut self.modules {
            module.shutdown(&mut self.context).await?;
        }
        
        for module in &mut self.ui_modules {
            module.shutdown(&mut self.context).await?;
        }
        
        Ok(())
    }
}

