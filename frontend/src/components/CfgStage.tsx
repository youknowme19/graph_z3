import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { usePrefersReducedMotion } from '../lib/motion';

interface BlockNode {
  id: string;
  name: string;
  addr: string;
  risk: number;
  role: 'entry' | 'guard' | 'sink' | 'lib' | 'exit';
  pos: [number, number, number];
}

const NODES: BlockNode[] = [
  { id: 'entry', name: 'main() prologue', addr: '0x1000004ac', risk: 0.12, role: 'entry', pos: [0, 2.2, 0] },
  { id: 'guard', name: 'validate_len()', addr: '0x100000558', risk: 0.47, role: 'guard', pos: [-2.2, 0.8, 0.6] },
  { id: 'sink', name: 'memcpy_chk sink', addr: '0x10000051c', risk: 0.94, role: 'sink', pos: [2.0, 0.4, -0.4] },
  { id: 'lib', name: 'plt_strcpy', addr: '0x1000008a0', risk: 0.31, role: 'lib', pos: [1.8, -1.2, 0.8] },
  { id: 'exit', name: 'epilogue_ret', addr: '0x100000580', risk: 0.08, role: 'exit', pos: [-0.6, -2.2, 0] },
];

const EDGES: Array<{ from: string; to: string; type: 'sat' | 'live' | 'pruned' }> = [
  { from: 'entry', to: 'guard', type: 'live' },
  { from: 'entry', to: 'sink', type: 'sat' },
  { from: 'guard', to: 'exit', type: 'pruned' },
  { from: 'sink', to: 'lib', type: 'sat' },
  { from: 'sink', to: 'exit', type: 'live' },
  { from: 'lib', to: 'exit', type: 'pruned' },
];

export const CfgStage: React.FC<{ className?: string; onSelectNode?: (nodeId: string) => void }> = ({
  className = '',
  onSelectNode,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const reduced = usePrefersReducedMotion();
  const [activeNode, setActiveNode] = useState<string>('sink');

  const selected = NODES.find((n) => n.id === activeNode) || NODES[2];

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 340;

    // Three.js Scene Setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 7.8);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Group for orbital rotation
    const graphGroup = new THREE.Group();
    scene.add(graphGroup);

    // Ambient and Point Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const emeraldLight = new THREE.PointLight(0x10b981, 2.5, 12);
    emeraldLight.position.set(2, 2, 4);
    scene.add(emeraldLight);

    const rubyLight = new THREE.PointLight(0xf43f5e, 2.0, 10);
    rubyLight.position.set(2, 0, 2);
    scene.add(rubyLight);

    // Create 3D Nodes
    const nodeMeshes: THREE.Mesh[] = [];
    const nodeLookup = new Map<string, THREE.Vector3>();

    NODES.forEach((n) => {
      const vec = new THREE.Vector3(...n.pos);
      nodeLookup.set(n.id, vec);

      const isSink = n.role === 'sink';
      const isEntry = n.role === 'entry';

      const geometry = new THREE.BoxGeometry(1.3, 0.55, 0.35);
      const color = isSink ? 0xf43f5e : isEntry ? 0x10b981 : 0x27272a;

      const material = new THREE.MeshStandardMaterial({
        color,
        roughness: 0.3,
        metalness: 0.2,
        transparent: true,
        opacity: 0.9,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.copy(vec);
      mesh.userData = { id: n.id };
      graphGroup.add(mesh);
      nodeMeshes.push(mesh);

      // Wireframe border for crisp minimalist look
      const wireGeometry = new THREE.EdgesGeometry(geometry);
      const wireMaterial = new THREE.LineBasicMaterial({
        color: isSink ? 0xff6b81 : isEntry ? 0x34d399 : 0x52525b,
        linewidth: 1,
      });
      const wireframe = new THREE.LineSegments(wireGeometry, wireMaterial);
      mesh.add(wireframe);
    });

    // Create 3D Edges
    EDGES.forEach((e) => {
      const p1 = nodeLookup.get(e.from);
      const p2 = nodeLookup.get(e.to);
      if (!p1 || !p2) return;

      const points = [p1, p2];
      const geometry = new THREE.BufferGeometry().setFromPoints(points);

      let material: THREE.Material;
      if (e.type === 'sat') {
        material = new THREE.LineBasicMaterial({ color: 0x10b981, linewidth: 2 });
      } else if (e.type === 'pruned') {
        material = new THREE.LineDashedMaterial({
          color: 0x3f3f46,
          dashSize: 0.2,
          gapSize: 0.15,
        });
      } else {
        material = new THREE.LineBasicMaterial({ color: 0x71717a, linewidth: 1 });
      }

      const line = new THREE.Line(geometry, material);
      if (e.type === 'pruned') line.computeLineDistances();
      graphGroup.add(line);
    });

    // Mouse tilt interaction
    let targetRotationX = 0.15;
    let targetRotationY = -0.2;

    const handleMouseMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      targetRotationY = x * 0.45;
      targetRotationX = -y * 0.35 + 0.1;
    };

    container.addEventListener('mousemove', handleMouseMove);

    // Raycaster for clicking nodes
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleClick = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const id = intersects[0].object.userData.id;
        if (id) {
          setActiveNode(id);
          onSelectNode?.(id);
        }
      }
    };

    container.addEventListener('click', handleClick);

    // Animation Loop
    let animationFrameId: number;
    const clock = new THREE.Clock();

    const animate = () => {

      if (!reduced) {
        graphGroup.rotation.y += (targetRotationY - graphGroup.rotation.y) * 0.05;
        graphGroup.rotation.x += (targetRotationX - graphGroup.rotation.x) * 0.05;

        // Subtle breathing
        const time = clock.getElapsedTime();
        rubyLight.intensity = 1.6 + Math.sin(time * 3) * 0.6;
        emeraldLight.intensity = 2.0 + Math.cos(time * 2) * 0.5;
      }

      renderer.render(scene, camera);
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight || 340;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      container.removeEventListener('mousemove', handleMouseMove);
      container.removeEventListener('click', handleClick);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement.parentElement) {
        renderer.domElement.parentElement.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [reduced, onSelectNode]);

  return (
    <div className={`flex flex-col rounded-xl border border-zinc-800 bg-zinc-900/60 backdrop-blur-sm p-4 ${className}`}>
      {/* 3D Scene Viewport */}
      <div className="relative h-72 w-full overflow-hidden rounded-lg bg-zinc-950/80 border border-zinc-800/60">
        <div ref={mountRef} className="h-full w-full cursor-pointer" />

        {/* Minimal header badge */}
        <div className="pointer-events-none absolute left-3 top-3 flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-400" />
          <span className="font-mono text-[10px] font-medium uppercase tracking-wider text-zinc-400">
            Interactive CFG · 3D VEX IR
          </span>
        </div>

        {/* Legend */}
        <div className="pointer-events-none absolute right-3 top-3 flex items-center gap-3 font-mono text-[10px] text-zinc-500">
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> SAT Path
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500" /> Vulnerable Sink
          </span>
        </div>

        {/* Click hint */}
        <div className="pointer-events-none absolute bottom-3 left-3 text-[10px] font-mono text-zinc-500">
          Click block to inspect SageConv score
        </div>
      </div>

      {/* Selected Block Quick Metadata */}
      {selected && (
        <div className="mt-3 grid grid-cols-3 gap-2 border-t border-zinc-800/80 pt-3 text-xs">
          <div className="rounded-md bg-zinc-900/80 p-2.5 border border-zinc-800/50">
            <span className="block font-mono text-[10px] uppercase text-zinc-500">Block</span>
            <span className="font-mono font-semibold text-zinc-200 truncate block mt-0.5">{selected.name}</span>
          </div>
          <div className="rounded-md bg-zinc-900/80 p-2.5 border border-zinc-800/50">
            <span className="block font-mono text-[10px] uppercase text-zinc-500">Address</span>
            <span className="font-mono text-zinc-300 block mt-0.5">{selected.addr}</span>
          </div>
          <div className="rounded-md bg-zinc-900/80 p-2.5 border border-zinc-800/50">
            <span className="block font-mono text-[10px] uppercase text-zinc-500">GraphSAGE Risk</span>
            <span className={`font-mono font-bold block mt-0.5 ${selected.risk > 0.8 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {(selected.risk * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
