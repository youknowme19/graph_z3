import React, { useEffect, useRef } from 'react';

export const ParallaxCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    let mouseX = width / 2;
    let mouseY = height / 2;
    let targetMouseX = width / 2;
    let targetMouseY = height / 2;

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    const handleMouseMove = (e: MouseEvent) => {
      targetMouseX = e.clientX;
      targetMouseY = e.clientY;
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove);

    // Particle nodes representing CFG state space
    interface Particle {
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      alpha: number;
      layer: number;
    }

    const particleCount = Math.min(65, Math.floor(width / 22));
    const particles: Particle[] = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 1.6 + 0.8,
        alpha: Math.random() * 0.45 + 0.15,
        layer: Math.random() * 2 + 1, // Depth layer for parallax
      });
    }

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Smooth mouse easing
      mouseX += (targetMouseX - mouseX) * 0.04;
      mouseY += (targetMouseY - mouseY) * 0.04;

      const offsetX = (mouseX - width / 2) * 0.03;
      const offsetY = (mouseY - height / 2) * 0.03;

      // Draw subtle grid
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.025)';
      ctx.lineWidth = 1;
      const gridSize = 48;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x + (offsetX * 0.2) % gridSize, 0);
        ctx.lineTo(x + (offsetX * 0.2) % gridSize, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y + (offsetY * 0.2) % gridSize);
        ctx.lineTo(width, y + (offsetY * 0.2) % gridSize);
        ctx.stroke();
      }

      // Update and connect particles
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = width;
        if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        if (p.y > height) p.y = 0;

        const posX = p.x + offsetX * p.layer;
        const posY = p.y + offsetY * p.layer;

        // Draw connections
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const posX2 = p2.x + offsetX * p2.layer;
          const posY2 = p2.y + offsetY * p2.layer;
          const dx = posX - posX2;
          const dy = posY - posY2;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 130) {
            const lineAlpha = (1 - dist / 130) * 0.12 * p.alpha;
            ctx.strokeStyle = `rgba(56, 189, 248, ${lineAlpha})`;
            ctx.lineWidth = 0.8;
            ctx.beginPath();
            ctx.moveTo(posX, posY);
            ctx.lineTo(posX2, posY2);
            ctx.stroke();
          }
        }

        // Draw node
        ctx.fillStyle = `rgba(96, 165, 250, ${p.alpha})`;
        ctx.beginPath();
        ctx.arc(posX, posY, p.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-80"
    />
  );
};
