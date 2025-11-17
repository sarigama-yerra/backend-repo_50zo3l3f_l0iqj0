"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogpost" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime


class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    email: EmailStr = Field(..., description="Email address (unique)")
    password_hash: str = Field(..., description="BCrypt hashed password")
    name: Optional[str] = Field(None, description="Display name")
    is_admin: bool = Field(False, description="Admin privileges")
    plan: str = Field("free", description="Subscription plan: free|pro")
    usage: Dict[str, int] = Field(default_factory=dict, description="Monthly usage counters keyed by YYYY-MM")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class UserConfig(BaseModel):
    """
    Per-user configuration
    Collection name: "userconfig"
    """
    user_id: str = Field(..., description="User ID (stringified ObjectId)")
    favorite_types: List[str] = Field(default_factory=lambda: [
        "feat", "fix", "chore", "docs", "refactor", "test", "perf", "ci", "build", "style"
    ])
    favorite_scopes: List[str] = Field(default_factory=list)
    footer_template: Optional[str] = Field(
        None,
        description="Footer template e.g. 'Refs: {ticket} | BREAKING CHANGE: {note}'"
    )
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class CommitHistory(BaseModel):
    """
    Generated commit messages history per user
    Collection name: "commithistory"
    """
    user_id: str = Field(..., description="User ID (stringified ObjectId)")
    git_status: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    type: str
    scope: Optional[str] = None
    message: str
    changelog_line: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
