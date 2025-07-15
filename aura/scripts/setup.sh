#!/bin/bash

# Aura Setup Script - Sets up development environment for zero-knowledge architecture

set -e

echo "🚀 Setting up Aura Development Environment"
echo "=========================================="

# Check requirements
echo "📋 Checking requirements..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3.11+ required but not found"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.11"

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"; then
    echo "❌ Python $REQUIRED_VERSION+ required, found $PYTHON_VERSION"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js 18+ required but not found"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker required but not found"
    exit 1
fi

echo "✅ All requirements satisfied"

# Setup backend
echo ""
echo "🐍 Setting up Python backend..."
cd backend

echo "📦 Installing Python dependencies..."
if command -v uv &> /dev/null; then
    echo "Using uv for faster installs..."
    uv pip install -e ".[dev,test]"
else
    python3 -m pip install -e ".[dev,test]"
fi

echo "🧪 Running backend tests..."
python3 -m pytest tests/ -v --tb=short

echo "✅ Backend setup complete"

# Setup frontend
cd ../frontend/web
echo ""
echo "🌐 Setting up frontend..."

echo "📦 Installing Node.js dependencies..."
npm install

echo "🧪 Running frontend tests..."
npm test -- --run --coverage

echo "🏗️ Building frontend..."
npm run build

echo "✅ Frontend setup complete"

# Setup infrastructure
cd ../../
echo ""
echo "🐳 Setting up infrastructure..."

echo "📊 Starting database services..."
docker-compose up -d postgres redis qdrant

echo "⏳ Waiting for services to be ready..."
sleep 10

echo "🗄️ Running database migrations..."
cd backend
python3 -c "
from aura.models.base import Base
from aura.core.database import engine
Base.metadata.create_all(bind=engine)
print('Database tables created successfully')
"

cd ..

echo ""
echo "🎯 Running integration demo..."
python3 scripts/demo.py

echo ""
echo "✅ Setup complete! Aura is ready for development."
echo ""
echo "📖 Quick Start Commands:"
echo "   Backend:  cd backend && python3 -m aura.main"
echo "   Frontend: cd frontend/web && npm run dev"
echo "   Tests:    cd backend && pytest"
echo "   Demo:     python3 scripts/demo.py"
echo ""
echo "🌐 URLs:"
echo "   Backend API:    http://localhost:3001"
echo "   Frontend:       http://localhost:3000"
echo "   API Docs:       http://localhost:3001/docs"
echo ""
echo "🔐 Privacy Features Ready:"
echo "   ✅ Zero-knowledge authentication"
echo "   ✅ Client-side encryption"
echo "   ✅ Encrypted storage"
echo "   ✅ Support access control"