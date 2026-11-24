/**
 * 3D Cyber Particle Globe Engine
 * Renders an interactive, rotating 3D digital earth with glowing nodes,
 * connecting data arcs, and atmospheric cyan aura on an HTML5 canvas.
 * Works 100% offline with zero external dependencies.
 */

class CyberGlobe {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.rotationY = 0;
        this.rotationX = 0.2;
        this.autoRotateSpeed = 0.0035;
        this.isDragging = false;
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        
        this.particles = [];
        this.arcs = [];
        this.glowPulse = 0;

        this.initSize();
        this.generateParticles();
        this.generateArcs();
        this.bindEvents();
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }

    initSize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = rect.width;
        this.height = Math.max(rect.height || 540, 500);
        this.canvas.width = this.width * window.devicePixelRatio;
        this.canvas.height = this.height * window.devicePixelRatio;
        this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
        this.radius = Math.min(this.width, this.height) * 0.36;
        this.centerX = this.width * 0.5;
        this.centerY = this.height * 0.5;
    }

    generateParticles() {
        this.particles = [];
        // Approximate continent distributions & digital cyber grid
        const rings = 45;
        for (let r = 0; r < rings; r++) {
            const phi = Math.acos(-1 + (2 * r) / rings);
            const count = Math.floor(Math.sin(phi) * 70);
            for (let i = 0; i < count; i++) {
                const theta = (2 * Math.PI * i) / count;
                
                // Add noise for continent clusters
                const isNode = (r % 5 === 0 && i % 4 === 0) || Math.random() < 0.04;
                
                this.particles.push({
                    x: Math.sin(phi) * Math.cos(theta),
                    y: Math.cos(phi),
                    z: Math.sin(phi) * Math.sin(theta),
                    isNode: isNode,
                    baseAlpha: isNode ? 0.9 : 0.45,
                    size: isNode ? 2.5 : 1.3,
                    pulseSpeed: 0.02 + Math.random() * 0.03,
                    pulsePhase: Math.random() * Math.PI * 2
                });
            }
        }
    }

    generateArcs() {
        this.arcs = [];
        // Connect key high-security nodes around the globe
        const nodes = this.particles.filter(p => p.isNode);
        for (let i = 0; i < 18; i++) {
            if (nodes.length < 2) break;
            const p1 = nodes[Math.floor(Math.random() * nodes.length)];
            const p2 = nodes[Math.floor(Math.random() * nodes.length)];
            if (p1 !== p2) {
                this.arcs.push({
                    p1: p1,
                    p2: p2,
                    progress: Math.random(),
                    speed: 0.005 + Math.random() * 0.008,
                    color: Math.random() > 0.4 ? 'rgba(0, 242, 254, ' : 'rgba(79, 172, 254, '
                });
            }
        }
    }

    bindEvents() {
        window.addEventListener('resize', () => this.initSize());

        this.canvas.addEventListener('mousedown', (e) => {
            this.isDragging = true;
            this.lastMouseX = e.clientX;
            this.lastMouseY = e.clientY;
        });

        window.addEventListener('mousemove', (e) => {
            if (!this.isDragging) return;
            const dx = e.clientX - this.lastMouseX;
            const dy = e.clientY - this.lastMouseY;
            this.rotationY += dx * 0.005;
            this.rotationX += dy * 0.005;
            this.rotationX = Math.max(-0.8, Math.min(0.8, this.rotationX));
            this.lastMouseX = e.clientX;
            this.lastMouseY = e.clientY;
        });

        window.addEventListener('mouseup', () => {
            this.isDragging = false;
        });

        // Touch support
        this.canvas.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1) {
                this.isDragging = true;
                this.lastMouseX = e.touches[0].clientX;
                this.lastMouseY = e.touches[0].clientY;
            }
        });

        window.addEventListener('touchmove', (e) => {
            if (!this.isDragging || e.touches.length !== 1) return;
            const dx = e.touches[0].clientX - this.lastMouseX;
            const dy = e.touches[0].clientY - this.lastMouseY;
            this.rotationY += dx * 0.006;
            this.rotationX += dy * 0.006;
            this.lastMouseX = e.touches[0].clientX;
            this.lastMouseY = e.touches[0].clientY;
        });

        window.addEventListener('touchend', () => {
            this.isDragging = false;
        });
    }

    rotatePoint(p) {
        // Rotate around X
        const cosX = Math.cos(this.rotationX);
        const sinX = Math.sin(this.rotationX);
        const y1 = p.y * cosX - p.z * sinX;
        const z1 = p.y * sinX + p.z * cosX;

        // Rotate around Y
        const cosY = Math.cos(this.rotationY);
        const sinY = Math.sin(this.rotationY);
        const x2 = p.x * cosY + z1 * sinY;
        const z2 = -p.x * sinY + z1 * cosY;

        return { x: x2, y: y1, z: z2 };
    }

    animate() {
        if (!this.isDragging) {
            this.rotationY += this.autoRotateSpeed;
        }
        this.glowPulse += 0.03;

        this.ctx.clearRect(0, 0, this.width, this.height);

        // 1. Draw Atmospheric Glow Behind Globe
        const glowRadius = this.radius * 1.25;
        const radialGradient = this.ctx.createRadialGradient(
            this.centerX, this.centerY, this.radius * 0.6,
            this.centerX, this.centerY, glowRadius
        );
        radialGradient.addColorStop(0, 'rgba(0, 150, 255, 0.15)');
        radialGradient.addColorStop(0.5, 'rgba(0, 242, 254, 0.08)');
        radialGradient.addColorStop(0.85, 'rgba(0, 80, 200, 0.03)');
        radialGradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
        
        this.ctx.fillStyle = radialGradient;
        this.ctx.beginPath();
        this.ctx.arc(this.centerX, this.centerY, glowRadius, 0, Math.PI * 2);
        this.ctx.fill();

        // Outer Neon Rim
        this.ctx.strokeStyle = `rgba(0, 242, 254, ${0.15 + Math.sin(this.glowPulse) * 0.05})`;
        this.ctx.lineWidth = 1.5;
        this.ctx.beginPath();
        this.ctx.arc(this.centerX, this.centerY, this.radius, 0, Math.PI * 2);
        this.ctx.stroke();

        // 2. Project Particles
        const projected = [];
        for (let i = 0; i < this.particles.length; i++) {
            const p = this.particles[i];
            const rotated = this.rotatePoint(p);
            
            // Perspective Projection
            const k = 400 / (400 - rotated.z * this.radius);
            const px = this.centerX + rotated.x * this.radius * k;
            const py = this.centerY + rotated.y * this.radius * k;
            
            projected.push({
                orig: p,
                x: px,
                y: py,
                z: rotated.z,
                isFront: rotated.z > -0.2
            });
        }

        // Sort by Z for realistic depth
        projected.sort((a, b) => a.z - b.z);

        // 3. Draw Connecting Cyber Mesh Lines
        this.ctx.lineWidth = 0.5;
        for (let i = 0; i < projected.length; i += 2) {
            const p1 = projected[i];
            if (!p1.isFront) continue;
            for (let j = i + 1; j < Math.min(i + 7, projected.length); j++) {
                const p2 = projected[j];
                if (!p2.isFront) continue;
                const distSq = (p1.x - p2.x) ** 2 + (p1.y - p2.y) ** 2;
                if (distSq < 1600) { // Within 40px
                    const alpha = (1 - distSq / 1600) * 0.18 * (p1.z + 1) * 0.5;
                    this.ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`;
                    this.ctx.beginPath();
                    this.ctx.moveTo(p1.x, p1.y);
                    this.ctx.lineTo(p2.x, p2.y);
                    this.ctx.stroke();
                }
            }
        }

        // 4. Draw Connecting Dynamic Arcs with Traveling Packets
        for (let i = 0; i < this.arcs.length; i++) {
            const arc = this.arcs[i];
            arc.progress += arc.speed;
            if (arc.progress > 1) arc.progress = 0;

            const r1 = this.rotatePoint(arc.p1);
            const r2 = this.rotatePoint(arc.p2);

            // Only draw if both are somewhat visible
            if (r1.z > -0.3 || r2.z > -0.3) {
                const p1x = this.centerX + r1.x * this.radius;
                const p1y = this.centerY + r1.y * this.radius;
                const p2x = this.centerX + r2.x * this.radius;
                const p2y = this.centerY + r2.y * this.radius;

                // Elevated control point for 3D curved arc
                const midX = (p1x + p2x) / 2;
                const midY = (p1y + p2y) / 2 - 40;

                this.ctx.strokeStyle = arc.color + '0.12)';
                this.ctx.lineWidth = 1;
                this.ctx.beginPath();
                this.ctx.moveTo(p1x, p1y);
                this.ctx.quadraticCurveTo(midX, midY, p2x, p2y);
                this.ctx.stroke();

                // Traveling Light Pulse Packet
                const t = arc.progress;
                const tx = (1 - t) * (1 - t) * p1x + 2 * (1 - t) * t * midX + t * t * p2x;
                const ty = (1 - t) * (1 - t) * p1y + 2 * (1 - t) * t * midY + t * t * p2y;

                this.ctx.fillStyle = '#ffffff';
                this.ctx.shadowColor = '#00f2fe';
                this.ctx.shadowBlur = 8;
                this.ctx.beginPath();
                this.ctx.arc(tx, ty, 2.2, 0, Math.PI * 2);
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
            }
        }

        // 5. Draw Particles
        for (let i = 0; i < projected.length; i++) {
            const pt = projected[i];
            const depthFactor = (pt.z + 1.2) / 2.2; // 0 to 1
            if (depthFactor <= 0) continue;

            const alpha = Math.max(0.08, pt.orig.baseAlpha * depthFactor);
            const size = Math.max(0.8, pt.orig.size * depthFactor);

            if (pt.orig.isNode) {
                // Pulsing glowing cybersecurity node
                const pulse = Math.sin(this.glowPulse * 2 + pt.orig.pulsePhase);
                const nodeSize = size * (1 + pulse * 0.25);
                
                this.ctx.fillStyle = `rgba(0, 242, 254, ${alpha})`;
                this.ctx.shadowColor = '#00f2fe';
                this.ctx.shadowBlur = 10;
                this.ctx.beginPath();
                this.ctx.arc(pt.x, pt.y, nodeSize + 1.5, 0, Math.PI * 2);
                this.ctx.fill();
                this.ctx.shadowBlur = 0;

                // Center white spark
                this.ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.9})`;
                this.ctx.beginPath();
                this.ctx.arc(pt.x, pt.y, nodeSize * 0.6, 0, Math.PI * 2);
                this.ctx.fill();
            } else {
                // Standard grid point
                this.ctx.fillStyle = `rgba(79, 172, 254, ${alpha * 0.75})`;
                this.ctx.beginPath();
                this.ctx.arc(pt.x, pt.y, size, 0, Math.PI * 2);
                this.ctx.fill();
            }
        }

        requestAnimationFrame(this.animate);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('cyberGlobeCanvas')) {
        new CyberGlobe('cyberGlobeCanvas');
    }
});
