package protocol

const (
	_                    = iota
	TypeClientHello byte = iota
	TypeServerHello
	TypeManifest
	TypeSyncPlan
	TypeUpload
	TypeUploadAck
	TypeSyncDone
	TypeError byte = 255
)

const maxFrameSize = 32 << 20

// Envelope представляет одно управляющее сообщение после выделения его границ.
type Envelope struct {
	Type byte
	Body []byte
}

// ClientHello приходит первым на каждом соединении и описывает его назначение.
type ClientHello struct {
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id,omitempty"`
	Role      string `json:"role"`
}

// ServerHello подтверждает, что сервер принял соединение и готов работать дальше.
type ServerHello struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
}

// ManifestRequest описывает текущее состояние клиентской директории.
type ManifestRequest struct {
	Files       []FileMeta `json:"files"`
	ForceUpload bool       `json:"force_upload"`
	Mode        string     `json:"mode"`
}

// SyncPlan содержит список файлов для отправки и удаления.
type SyncPlan struct {
	Upload []FileMeta `json:"upload"`
	Delete []string   `json:"delete"`
}

// FileMeta описывает один файл.
type FileMeta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// UploadRequest открывает передачу конкретного файла.
type UploadRequest struct {
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	TransferMode string `json:"transfer_mode"`
}

// UploadAck подтверждает успешный прием файла.
type UploadAck struct {
	Name    string `json:"name"`
	Stored  bool   `json:"stored"`
	Message string `json:"message"`
}

// SyncDone завершает раунд синхронизации и возвращает сводку результата.
type SyncDone struct {
	Uploaded      int      `json:"uploaded"`
	UploadedBytes int64    `json:"uploaded_bytes"`
	Deleted       []string `json:"deleted"`
	TransferMode  string   `json:"transfer_mode"`
	Message       string   `json:"message"`
}

// ErrorMessage передает человекочитаемое описание ошибки.
type ErrorMessage struct {
	Message string `json:"message"`
}

// ConvertFiles превращает список файлов в словарь по имени.
func ConvertFiles(files []FileMeta) map[string]FileMeta {
	result := make(map[string]FileMeta, len(files))
	for _, file := range files {
		result[file.Name] = file
	}

	return result
}
