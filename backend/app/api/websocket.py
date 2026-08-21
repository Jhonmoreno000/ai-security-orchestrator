import json
from datetime import datetime
from typing import Dict, List, Set
from uuid import UUID

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.schemas.websocket import (
    WSEventType,
    WSJobCompleted,
    WSJobProgress,
    WSScanFinished,
    WSScanStarted,
    WSError,
    WSPing,
    WSPong,
)

logger = structlog.get_logger()

router = APIRouter()


class ConnectionManager:
    """Gestor de conexiones WebSocket por scan_id.

    Administra la lista de conexiones activas y permite
    transmitir eventos de estado durante un scan.
    """

    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}
        self._all_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket, scan_id: str) -> None:
        """Acepta y registra una conexión WebSocket."""
        await websocket.accept()
        self._all_connections.add(websocket)

        if scan_id not in self._connections:
            self._connections[scan_id] = []
        self._connections[scan_id].append(websocket)

        logger.info("ws_connected", scan_id=scan_id, total=len(self._all_connections))

    def disconnect(self, websocket: WebSocket, scan_id: str) -> None:
        """Remueve una conexión WebSocket."""
        self._all_connections.discard(websocket)

        if scan_id in self._connections:
            if websocket in self._connections[scan_id]:
                self._connections[scan_id].remove(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]

        logger.info("ws_disconnected", scan_id=scan_id, total=len(self._all_connections))

    async def broadcast_to_scan(self, scan_id: str, message: dict) -> None:
        """Envía un mensaje a todas las conexiones de un scan específico."""
        if scan_id not in self._connections:
            return

        dead = []
        for ws in self._connections[scan_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws, scan_id)

    async def broadcast_all(self, message: dict) -> None:
        """Envía un mensaje a todas las conexiones activas."""
        dead = []
        for ws in self._all_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._all_connections.discard(ws)

    async def send_scan_started(
        self,
        scan_id: str,
        target: str,
        scanners: List[str],
    ) -> None:
        """Emite evento SCAN_STARTED."""
        event = WSScanStarted(
            scan_id=scan_id,
            data={
                "target": target,
                "scanners": scanners,
                "message": f"Scan started for {target}",
            },
        )
        await self.broadcast_to_scan(scan_id, event.model_dump(mode="json"))

    async def send_job_progress(
        self,
        scan_id: str,
        scanner: str,
        progress_percent: int = 0,
        message: str = "",
    ) -> None:
        """Emite evento JOB_PROGRESS."""
        event = WSJobProgress(
            scan_id=scan_id,
            data={
                "scanner": scanner,
                "status": "running",
                "progress_percent": progress_percent,
                "message": message or f"{scanner} is running",
            },
        )
        await self.broadcast_to_scan(scan_id, event.model_dump(mode="json"))

    async def send_job_completed(
        self,
        scan_id: str,
        scanner: str,
        exit_code: int,
        findings_count: int,
        duration_ms: int,
        message: str = "",
    ) -> None:
        """Emite evento JOB_COMPLETED."""
        event = WSJobCompleted(
            scan_id=scan_id,
            data={
                "scanner": scanner,
                "status": "completed" if exit_code == 0 else "failed",
                "exit_code": exit_code,
                "findings_count": findings_count,
                "duration_ms": duration_ms,
                "message": message or f"{scanner} finished",
            },
        )
        await self.broadcast_to_scan(scan_id, event.model_dump(mode="json"))

    async def send_scan_finished(
        self,
        scan_id: str,
        status: str,
        total_findings: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        info: int,
        duration_ms: int,
        message: str = "",
    ) -> None:
        """Emite evento SCAN_FINISHED."""
        event = WSScanFinished(
            scan_id=scan_id,
            data={
                "status": status,
                "total_findings": total_findings,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "duration_ms": duration_ms,
                "message": message or "Scan finished",
            },
        )
        await self.broadcast_to_scan(scan_id, event.model_dump(mode="json"))

    async def send_error(
        self,
        scan_id: str,
        error: str,
        scanner: str | None = None,
    ) -> None:
        """Emite evento ERROR."""
        event = WSError(
            scan_id=scan_id,
            data={
                "error": error,
                "scanner": scanner,
            },
        )
        await self.broadcast_to_scan(scan_id, event.model_dump(mode="json"))

    @property
    def active_connections(self) -> int:
        return len(self._all_connections)

    @property
    def active_scans(self) -> List[str]:
        return list(self._connections.keys())


manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    """Endpoint WebSocket para recibir eventos de un scan específico.

    Se conecta a: ws://host/ws/scan/{scan_id}
    """
    await manager.connect(websocket, scan_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("event") == "PING":
                    pong = WSPong(scan_id=scan_id)
                    await websocket.send_json(pong.model_dump(mode="json"))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
    except Exception as e:
        logger.error("ws_error", scan_id=scan_id, error=str(e))
        manager.disconnect(websocket, scan_id)


@router.websocket("/ws/global")
async def websocket_global(websocket: WebSocket):
    """Endpoint WebSocket para recibir todos los eventos globales.

    Se conecta a: ws://host/ws/global
    """
    await manager.connect(websocket, "__global__")
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("event") == "PING":
                    pong = WSPong(scan_id="global")
                    await websocket.send_json(pong.model_dump(mode="json"))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, "__global__")
    except Exception as e:
        logger.error("ws_error_global", error=str(e))
        manager.disconnect(websocket, "__global__")
