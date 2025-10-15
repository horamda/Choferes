from pydantic import BaseModel, Field, validator
from typing import Optional, List
import re

class LoginRequest(BaseModel):
    dni: str = Field(..., min_length=7, max_length=8, description="DNI del empleado")

    @validator('dni')
    def validate_dni(cls, v):
        if not re.match(r'^\d{7,8}$', v):
            raise ValueError('DNI debe contener entre 7 y 8 dígitos')
        return v

class TokenRegistration(BaseModel):
    dni: str = Field(..., min_length=7, max_length=8)
    token: str = Field(..., min_length=10, max_length=500)

    @validator('dni')
    def validate_dni(cls, v):
        if not re.match(r'^\d{7,8}$', v):
            raise ValueError('DNI debe contener entre 7 y 8 dígitos')
        return v

class AsistenciaRequest(BaseModel):
    dni: str
    reunion_id: int = Field(..., gt=0)
    lat: float = Field(..., ge=-90, le=90)
    lon: float = Field(..., ge=-180, le=180)

class PedidoRequest(BaseModel):
    dni: str
    sucursal_id: int = Field(..., gt=0)
    observaciones: Optional[str] = Field(None, max_length=500)
    items: List[dict] = Field(..., min_items=1)

class EmpleadoCreate(BaseModel):
    dni: str = Field(..., min_length=7, max_length=8)
    nombre: str = Field(..., min_length=2, max_length=100)
    sector: str = Field(..., min_length=2, max_length=50)
    sucursal_id: int = Field(..., gt=0)

    @validator('dni')
    def validate_dni(cls, v):
        if not re.match(r'^\d{7,8}$', v):
            raise ValueError('DNI debe contener entre 7 y 8 dígitos')
        return v

    @validator('nombre', 'sector')
    def sanitize_text(cls, v):
        if not v:
            return v
        # Remover caracteres de control
        v = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(v))
        return v.strip()

class IndicadorCreate(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    sector_id: int = Field(..., gt=0)
    activo: bool = True
    tipo_grafico: Optional[str] = None
    color_grafico: Optional[str] = None
    fill_grafico: Optional[bool] = None

class ReunionCreate(BaseModel):
    titulo: str = Field(..., min_length=2, max_length=200)
    frecuencia: str = Field(..., pattern=r'^(diaria|semanal|mensual)$')
    dia_semana: int = Field(..., ge=0, le=6)
    hora: str = Field(..., pattern=r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$')
    latitud: float = Field(..., ge=-90, le=90)
    longitud: float = Field(..., ge=-180, le=180)