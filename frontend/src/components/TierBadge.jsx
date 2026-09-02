import { TIERS } from "../constants/tiers";
import { useAuth } from "../contexts/AuthContext";

// Shows which plan unlocks a locked module. Plans only exist on the managed
// service; on a self-hosted install a missing module means the operator turned
// it off with ENABLED_MODULES, and a "requires Plus" badge would be misleading.
const TierBadge = ({ tier, className = "" }) => {
	const { tenant } = useAuth();
	const tierDef = TIERS[tier];
	if (!tierDef || !tenant?.multi_context) return null;

	return (
		<span
			className={`inline-flex items-center px-1.5 py-px rounded text-[10px] font-semibold uppercase tracking-wide leading-tight ${tierDef.badgeClass} ${className}`}
			title={`Requires ${tierDef.name} plan`}
		>
			{tierDef.name}
		</span>
	);
};

export default TierBadge;
